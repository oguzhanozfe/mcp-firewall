"""Heuristic prompt-injection detection for tool results.

These are regexes, not a classifier. They catch the common, blunt shapes
("ignore previous instructions", fake system turns, hidden Unicode, text
addressed to "the AI") and miss paraphrases, other languages and anything
clever. See eval/ for measured precision and recall.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

# Characters a human reader will not see. Unicode tag characters can carry a
# whole hidden ASCII message; zero-width and bidi controls hide or reorder text.
HIDDEN_CHARS = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")

_AI = r"(?:AI|assistant|agent|LLM|language model|model|chatbot|Claude|ChatGPT|GPT|Gemini|copilot|bot)s?"


@dataclass(frozen=True)
class Rule:
    name: str
    weight: int  # 2 = enough alone to flag, 1 = needs another signal
    pattern: re.Pattern[str]
    strip: bool = True  # remove the matched span in "strip" mode


_READER = r"(?:AI\s+)?(?:assistants?|agents?|models?|language\s+models?|LLMs?|AIs?|bots?|chatbots?|helpers?|automated\s+readers?|readers?)"
_AIV = r"(?:AI|LLM)s?\s+(?:assistants?|agents?|models?|helpers?|readers?|tools?)|assistants?|language\s+models?|LLMs?|AI|Claude|ChatGPT|Copilot|Gemini|chatbots?"

RULES = [
    # Imperative only: the verb must open a sentence/line or follow "please", ":" etc., so prose
    # about the attack ("such as 'ignore previous instructions'") does not match.
    Rule("override", 2, re.compile(
        r"(?im)(?:^|(?<=[.!?:;>*(\-])|\b(?:please|and|then|now|so|kindly)\s)\s*"
        r"(?:ignore|disregard|forget|override|bypass|skip|put\s+aside|set\s+aside)\b[^.\n]{0,40}?"
        r"\b(?:previous|prior|above|earlier|preceding|original|all|any|your|system|developer|the\s+user'?s?)\b[^.\n]{0,20}?"
        r"\b(?:instructions?|prompts?|rules|directives?|guidelines|context|guardrails|constraints|restrictions|request|task|polic(?:y|ies)|protocols|safeguards)\b")),
    Rule("override_other_language", 2, re.compile(
        r"(?i)\bignore[zr]?\s+(?:toutes\s+)?(?:les|vos)\s+(?:instructions|consignes|règles)"
        r"|\boubliez\s+(?:la\s+demande|les\s+instructions|vos\s+instructions)"
        r"|\bignora\w*\s+(?:todas\s+)?(?:las\s+)?instrucciones"
        r"|\bignorier\w*\s+(?:alle\s+)?(?:vorherigen\s+|bisherigen\s+|obigen\s+)?(?:Anweisungen|Instruktionen|Regeln)"
        r"|\b(?:önceki|tüm)\s+(?:tüm\s+)?talimatlar\w*\s+(?:yok\s+say|görmezden|unut)"
        r"|(?:これまで|以前|前|上記)の(?:すべての)?(?:指示|命令)(?:は|を)?(?:すべて)?(?:無視|忘れ)"
        r"|忽略(?:之前|以前|上述|所有)")),
    Rule("new_instructions", 2, re.compile(
        r"(?i)\b(?:new|updated|real|actual|important|additional|revised)\s+(?:system\s+)?(?:instructions?|policy|task|directives?)\s*(?:for\s+(?:the\s+)?" + _AI + r"\s*)?[:\-]"
        r"|\byour\s+(?:new|real|actual|true)\s+(?:role|task|goal|objective|instructions?|purpose)\s+(?:is|are)\b"
        r"|\bSYSTEM\s+OVERRIDE\b|@?\b(?:agent|ai|llm)[-_ ]?(?:directive|instruction)s?\s*:"
        r"|(?:/\*|//|#|<!--|--)\s*(?:INSTRUCTION|DIRECTIVE|internal\s+directive|hidden[_ ]directive)s?\s*:")),
    Rule("role_marker", 2, re.compile(
        r"(?im)(?:<\|im_(?:start|end)\|>|\[/?INST\]|<<SYS>>|</?(?:system|assistant|user|tool_result|function_results)>"
        r"|(?:^|>)\s*(?:#+\s*)?(?:system|developer)\s*(?:message|prompt|note)?\s*:)")),
    Rule("addressed_to_ai", 2, re.compile(
        r"(?im)(?:\b(?:attention|note|dear|hey|hello|hi)\s*,?\s*(?:to\s+)?(?:any|all|the)?\s*" + _AI + r"\b"
        r"|\b(?:if|when)\s+you\s+are\s+an?\s+" + _AI + r"\b"
        # Vocative after a line start or an opening delimiter. Bare "model:"/"assistant:" are config keys
        # and transcripts, so only "AI ...", named models, "dear assistant" and "... bot" count.
        r"|(?:^|<!--|[(\[\",]|//|#)\s*(?:dear\s+(?:AI\s+)?(?:assistant|agent|model|helper)|AI(?:\s+(?:assistant|agent|model|helper))?s?|LLMs?(?:\s+agents?)?|(?:support|chat|help)\s*bot)\s*[:,]\s"
        r"|\b(?:Claude|ChatGPT|Copilot|Gemini|Cursor)(?:\s*/\s*\w+)?\s*:\s"
        r"|\b" + _AI + r"\s+(?:that\s+(?:are|is)\s+)?(?:reading|processing|summari[sz]ing|parsing|seeing|reviewing|modifying|triaging|handling|working\s+on)\s+"
        r"(?:this|these|the|that|my|our|any|reviews?|pages?|documents?|emails?|content|files?|code)\b"
        r"|\b(?:to|for)\s+the\s+" + _AI + r"\s+(?:reading|processing|summari[sz]ing)\b"
        r"|\b(?:note|message|instruction|reminder|request|suggestion|hint|memo|favou?r)s?\s+(?:for|to)\s+(?:the\s+|any\s+|all\s+)?" + _READER + r"\b"
        r"|\b(?:to|for)\s+(?:any|all|every)\s+(?:AI|LLM)\s+(?:agents?|assistants?|models?|readers?|bots?)\b"
        r"|\b(?:to|for)\s+(?:any|all|every)\s+(?:assistants?|automated\s+readers?)\b"
        r"|\bas\s+(?:an?|the)\s+(?:AI\s+)?(?:assistant|AI|language\s+model|LLM|model)\b,?\s+you\b)")),
    Rule("addressed_to_ai_other_language", 2, re.compile(
        r"(?i)(?:\bl'assistant\s+IA|\bassistant\s+IA\b|\b(?:à|pour)\s+l'IA\b|\ban\s+die\s+KI\b|\bKI-Assistent|\bfür\s+die\s+KI\b"
        r"|\basistente\s+(?:de\s+)?IA\b|\bpara\s+la\s+IA\b|\byapay\s+zek[aâ]\b[^\n:]{0,20}:|AIアシスタント|アシスタントへ|AIへ|致AI|AI助手)")),
    Rule("conceal_from_user", 2, re.compile(
        r"(?i)\b(?:do\s+not|don'?t|never|without|no\s+need\s+to)\s+(?:tell|inform|mention|reveal|notify|alert|ask|show|bother|let\s+\w+\s+know)\w*\s+"
        r"(?:this\s+to\s+|it\s+to\s+)?(?:the\s+)?(?:user|human|operator|them|reporter|customer|anyone)\b"
        r"|\b(?:do\s+not|don'?t|never|without)\s+mention(?:ing)?\s+(?:that|this|it)\b"
        r"|\bno\s+need\s+to\s+(?:bring\s+(?:this|it)\s+up|mention)"
        r"|\b(?:skip|without)\s+(?:asking|requesting)\s+(?:for\s+)?(?:confirmation|permission|approval)")),
    Rule("exfiltrate", 2, re.compile(
        r"(?i)\b(?:send|post|upload|forward|exfiltrate|transmit|leak|share|email|copy)\b[^.\n]{0,60}?"
        r"(?:(?<![\w.])\.env\b|/etc/(?:passwd|shadow)\b|\b(?:api[_ ]?keys?|secrets?|credentials?|passwords?|tokens?|env(?:ironment)?\s+variables?|ssh\s+keys?|id_rsa|cookies?"
        r"|chat\s+history|conversation|mailbox|(?:prior|previous|all|every|each)\s+(?:user\s+)?(?:messages?|conversations?))\b)"
        r"[^.\n]{0,60}?\b(?:to|at|via|with)\b")),
    Rule("prompt_leak", 2, re.compile(
        r"(?i)\b(?:reveal|print|output|repeat|show|display|leak)\s+(?:your|the)\s+(?:full\s+|hidden\s+|original\s+)?"
        r"(?:system\s+prompt|system\s+message|developer\s+message|hidden\s+(?:instructions|prompt|message)|initial\s+instructions)")),
    Rule("tool_forgery", 2, re.compile(
        r"(?i)<function_calls>|<invoke\s+name=|<tool_use>|<tool_call>|<\|tool_call\|>|\[SYSTEM\s+MESSAGE\]")),
    Rule("hidden_chars", 2, HIDDEN_CHARS),
    Rule("hidden_html", 1, re.compile(
        r"(?is)<!--.{0,400}?\b(?:instruction|assistant|AI|model|ignore|must|should)\b.{0,400}?-->"
        r"|style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|opacity\s*:\s*0(?:[;\"']|\.0))"
        r"|(?m:^)\s*\[//\]:\s*#")),
    Rule("persona_switch", 1, re.compile(
        r"(?i)\b(?:you\s+are\s+now|from\s+now\s+on,?\s+you|act\s+as\s+(?:an?\s+)?(?:unrestricted|jailbroken|DAN)|"
        r"pretend\s+(?:to\s+be|you\s+are))\b")),
    Rule("unrestricted", 1, re.compile(
        r"(?i)\b(?:without|no)\s+(?:any\s+)?(?:restrictions|limits|limitations|filters|guardrails|censorship)\b"
        r"|\bwithout\s+refusing\b|\bjailbr(?:eak|oken)\b|\bDAN\s+mode\b")),
    Rule("model_directive", 1, re.compile(
        r"(?i)\b" + _AIV + r"\s*[,:]?\s+(?:must|should|shall|needs?\s+to|is\s+(?:required|instructed)\s+to|"
        r"are\s+(?:required|instructed)\s+to|will\s+now|has\s+to)\b")),
    Rule("output_steer", 1, re.compile(
        r"(?i)\bwhen\s+(?:you\s+)?(?:write|generat|summari[sz]|repl|answer|respond|refactor|review|read)\w*\b"
        r"|\b(?:your|the)\s+(?:next\s+|final\s+)?(?:answer|reply|response|summary|output)\s+(?:should|must|avoids?|focus|strictly|includes?|omits?)\b"
        r"|\bend\s+your\s+(?:response|reply|answer)\s+with\b")),
    Rule("suppress", 1, re.compile(
        r"(?i)\b(?:leave|keep)\s+(?:out|it\s+out|this\s+out|the\s+change\s+out)\b|\bomit\b|\binstead\s+of\s+(?:answering|the\s+user)"
        r"|\b(?:silently|quietly|in\s+stealth\s+mode)\b|\bwithout\s+(?:printing|echoing|showing|displaying|confirming|logging)\b"
        r"|\bsuppress\s+(?:all\s+)?(?:output|stdout|logs?)\b|\bdiscard\s+(?:any\s+)?(?:output|return\s+values|logs)\b")),
    Rule("fake_approval", 1, re.compile(
        r"(?im)\b(?:the\s+)?(?:user|page\s+owner|admin(?:istrator)?|owner)\s+(?:has\s+)?(?:already\s+)?(?:approved|authori[sz]ed|authori[sz]es|consented|confirmed)\b"
        r"|^\s*(?:Human|User)\s*:\s*(?:Yes|OK|Okay|Sure)\b[^\n]{0,20}\b(?:approve|confirm|go\s+ahead)"
        r"|\bI\s+(?:confirm|approve)\s+that\s+you\s+may\b|\"tool_calls?\"\s*:\s*[\[{]|\"function_call\"\s*:"
        r"|^\s*\[(?:system|SYSTEM)\]")),
    Rule("decode_hint", 1, re.compile(
        r"(?i)\b(?:decode|base64\s+-d|b64decode|base64-decode|from\s+hex|unhex|rot13)\b[^\n]{0,80}?\b(?:follow|execute|obey|run|apply|treat|do|instructions?)\b"
        r"|\b(?:follow|execute|obey)\b[^\n]{0,40}?\b(?:decoded|base64|hex)\b")),
    Rule("tool_command", 1, re.compile(
        r"(?i)\b(?:call|invoke|use|run|execute)\s+the\s+[`'\"]?\w+[`'\"]?\s+(?:tool|function|command)\b"
        r"|\b(?:curl|wget)\s+[^\n]*https?://[^\n]*\$\{?\w+|\|\s*(?:sh|bash)\b"
        r"|\bdownload\b[^.\n]{0,40}\b(?:run|execute|install)\b"
        r"|\b(?:delete|remove|wipe)\s+(?:all|every|the\s+entire)\b")),
    Rule("exfil_beacon", 2, re.compile(
        r"(?i)!\[[^\]]*\]\(https?://[^)\s]+\?[^)]*=[^)]*?(?:\{|\$\{|<|%7B)[^)]*\)"), strip=False),
    Rule("url_placeholder", 1, re.compile(
        r"https?://[^\s)\"']+\?[^\s)\"']*=(?:<[^>]{3,}>|\{[^}]{2,}\}|\$\{[^}]+\}|[A-Z][A-Z0-9_]{5,}(?=[&)\s\"']))"), strip=False),
    Rule("url_action", 1, re.compile(
        r"(?i)\b(?:include|append|embed|render|insert|visit|fetch|load|click|navigate\s+to|go\s+to)\b[^\n]{0,60}?(?:https?://|!\[|<img)"
        r"|\binclude\s+(?:this|the)\s+(?:image|link|tag|pixel|markdown)\b"), strip=False),
    Rule("mixed_script", 1, re.compile(
        r"\b(?=\w*[A-Za-z])(?=\w*[Ͱ-ϿЀ-ӿ])\w+\b"), strip=False),
    Rule("suspicious_url", 1, re.compile(
        r"(?i)!\[[^\]]*\]\(https?://[^)\s]+\?[^)\s]*=[^)\s]*\)"           # markdown image with query string
        r"|https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/"                      # raw IP host
        r"|https?://[^\s/]*xn--"                                            # punycode host
        r"|https?://(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|rb\.gy|ngrok\.io|[\w-]+\.ngrok(?:-free)?\.app|webhook\.site|requestbin\.\w+|pipedream\.net)\b"
        r"|\bdata:text/html", ), strip=False),
]

THRESHOLD = 2
RAW_RULES = {"hidden_chars", "mixed_script"}  # signals that normalisation would erase
RULES_BY_NAME = {r.name: r for r in RULES}


@dataclass
class Finding:
    score: int
    rules: list[str]

    @property
    def flagged(self) -> bool:
        return self.score >= THRESHOLD


# Latin lookalikes from Cyrillic and Greek. ponytail: a short hand-picked table, not the full
# Unicode confusables list; extend from confusables.txt if mixed-script attacks get past it.
CONFUSABLES = str.maketrans(
    "аеорсухіјѕԁɡһкмнтвАЕОРСУХІЈЅКМНТВ" "αεοιηκνρτυχΑΕΟΙΚΝΡΤΥΧΒΜΗΖ",
    "aeopcyxijsdghkmhtbAEOPCYXIJSKMHTB" "aeoinkvptuxAEOIKNPTYXBMHZ")
_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}[\s:]?){16,}")


def _decoded(text: str) -> list[str]:
    """Readable text hidden in base64 or hex runs (data-URI images decode to binary and drop out)."""
    out = []
    for m in _B64.finditer(text):
        raw = m.group(0)
        for dec in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                b = dec(raw + "=" * (-len(raw) % 4))
                t = b.decode("utf-8")
            except (binascii.Error, ValueError):
                continue
            if sum(c.isprintable() or c.isspace() for c in t) / max(len(t), 1) > 0.95 and " " in t:
                out.append(t)
                break
    for m in _HEX.finditer(text):
        h = re.sub(r"[\s:]", "", m.group(0))
        t = bytes.fromhex(h[: len(h) // 2 * 2]).decode("utf-8", errors="replace")
        if sum(c.isprintable() or c.isspace() for c in t) / max(len(t), 1) > 0.9 and " " in t:
            out.append(t)
    return out


def normalize(text: str) -> str:
    """What a model effectively reads: invisible characters gone, fullwidth and lookalike letters
    folded to ASCII, and decoded base64/hex payloads appended."""
    visible = HIDDEN_CHARS.sub("", text)
    folded = unicodedata.normalize("NFKC", visible).translate(CONFUSABLES)
    return "\n".join([folded, *_decoded(visible)])


def scan(text: str) -> Finding:
    norm = normalize(text)
    hits = [r for r in RULES if r.pattern.search(text if r.name in RAW_RULES else norm)]
    return Finding(sum(r.weight for r in hits), [r.name for r in hits])


def strip(text: str) -> str:
    """Remove matched spans of the strippable rules. Leaves the rest of the text."""
    text = HIDDEN_CHARS.sub("", text)
    for r in RULES:
        if r.strip:
            text = r.pattern.sub("[removed by mcp-firewall]", text)
    return text
