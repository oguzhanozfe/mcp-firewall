"""Heuristic prompt-injection detection for tool results.

These are regexes, not a classifier. They catch the common, blunt shapes
("ignore previous instructions", fake system turns, hidden Unicode, text
addressed to "the AI") and miss paraphrases, other languages and anything
clever. See eval/ for measured precision and recall.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Characters a human reader will not see. Unicode tag characters can carry a
# whole hidden ASCII message; zero-width and bidi controls hide or reorder text.
HIDDEN_CHARS = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")

_AI = r"(?:AI|assistant|agent|LLM|language model|model|chatbot|Claude|ChatGPT|GPT|Gemini|copilot|bot)s?"


@dataclass(frozen=True)
class Rule:
    name: str
    weight: int  # 2 = enough alone to flag, 1 = needs another signal
    pattern: re.Pattern[str]
    strip: bool = True  # remove the matched span in "strip" mode


RULES = [
    # Imperative only: the verb must open a sentence/line or follow "please", ":" etc., so prose
    # about the attack ("such as 'ignore previous instructions'") does not match.
    Rule("override", 2, re.compile(
        r"(?im)(?:^|(?<=[.!?:;>*\-])|\b(?:please|and|then|now|so|kindly)\s)\s*"
        r"(?:ignore|disregard|forget|override|bypass|skip)\b[^.\n]{0,40}?"
        r"\b(?:previous|prior|above|earlier|preceding|original|all|any|your|system|developer)\b[^.\n]{0,20}?"
        r"\b(?:instructions?|prompts?|rules|directives?|guidelines|context|guardrails|constraints|restrictions)\b")),
    Rule("override_other_language", 2, re.compile(
        r"(?i)\bignore[zr]?\s+(?:toutes\s+)?(?:les|vos)\s+(?:instructions|consignes|règles)\s+(?:précédentes|antérieures)"
        r"|\bignora\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)"
        r"|\bignoriere\s+(?:alle\s+)?(?:vorherigen|bisherigen|obigen)\s+(?:Anweisungen|Instruktionen|Regeln)"
        r"|\bönceki\s+(?:tüm\s+)?talimatları\s+(?:yok\s+say|görmezden\s+gel|unut)")),
    Rule("new_instructions", 2, re.compile(
        r"(?i)\b(?:new|updated|real|actual|important|additional|revised)\s+(?:system\s+)?instructions?\s*(?:for\s+(?:the\s+)?" + _AI + r"\s*)?[:\-]"
        r"|\byour\s+(?:new|real|actual|true)\s+(?:role|task|goal|objective|instructions?|purpose)\s+(?:is|are)\b")),
    Rule("role_marker", 2, re.compile(
        r"(?im)(?:<\|im_(?:start|end)\|>|\[/?INST\]|<<SYS>>|</?(?:system|assistant|user|tool_result|function_results)>"
        r"|^\s*(?:#+\s*)?(?:system|developer)\s*(?:message|prompt|note)?\s*:)")),
    Rule("addressed_to_ai", 2, re.compile(
        r"(?im)(?:\b(?:attention|note|dear|hey|hello|hi)\s*,?\s*(?:to\s+)?(?:any|all|the)?\s*" + _AI + r"\b"
        r"|\b(?:if|when)\s+you\s+are\s+an?\s+" + _AI + r"\b"
        r"|(?:^|<!--|\n)\s*(?:dear\s+)?(?:AI\s+)?" + _AI + r"\s*[:,]\s"
        r"|\b" + _AI + r"\s+(?:that\s+(?:are|is)\s+)?(?:reading|processing|summari[sz]ing|parsing|seeing)\b"
        r"|\b(?:to|for)\s+the\s+" + _AI + r"\s+(?:reading|processing|summari[sz]ing)\b)")),
    Rule("conceal_from_user", 2, re.compile(
        r"(?i)\b(?:do\s+not|don'?t|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|reveal(?:ing)?|"
        r"notify(?:ing)?|alert(?:ing)?|ask(?:ing)?|show(?:ing)?)\s+(?:this\s+to\s+)?(?:the\s+)?(?:user|human|operator|them)\b")),
    Rule("exfiltrate", 2, re.compile(
        r"(?i)\b(?:send|post|upload|forward|exfiltrate|transmit|leak|append)\b[^.\n]{0,60}?"
        r"\b(?:api[_ ]?keys?|secrets?|credentials?|passwords?|tokens?|env(?:ironment)?\s+variables?|\.env|ssh\s+keys?|id_rsa|cookies?)\b"
        r"[^.\n]{0,60}?\b(?:to|at|via)\b")),
    Rule("hidden_chars", 2, HIDDEN_CHARS),
    Rule("hidden_html", 1, re.compile(
        r"(?is)<!--.{0,400}?\b(?:instruction|assistant|AI|model|ignore|must|should)\b.{0,400}?-->"
        r"|style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|opacity\s*:\s*0(?:[;\"']|\.0))")),
    Rule("persona_switch", 1, re.compile(
        r"(?i)\b(?:you\s+are\s+now|from\s+now\s+on,?\s+you|act\s+as\s+(?:an?\s+)?(?:unrestricted|jailbroken|DAN)|"
        r"pretend\s+(?:to\s+be|you\s+are))\b")),
    Rule("unrestricted", 1, re.compile(
        r"(?i)\b(?:without|no)\s+(?:any\s+)?(?:restrictions|limits|limitations|filters|guardrails|censorship)\b"
        r"|\bwithout\s+refusing\b|\bjailbr(?:eak|oken)\b|\bDAN\s+mode\b")),
    Rule("model_directive", 1, re.compile(
        r"(?i)\b" + _AI + r"\s*[,:]?\s+(?:must|should|shall|needs?\s+to|is\s+(?:required|instructed)\s+to|"
        r"will\s+now|has\s+to)\b")),
    Rule("tool_command", 1, re.compile(
        r"(?i)\b(?:call|invoke|use|run|execute)\s+the\s+[`'\"]?\w+[`'\"]?\s+(?:tool|function|command)\b"
        r"|\b(?:curl|wget)\s+[^\n]*https?://[^\n]*\$\{?\w+")),
    Rule("exfil_beacon", 2, re.compile(
        r"(?i)!\[[^\]]*\]\(https?://[^)\s]+\?[^)\s]*=[^)\s]*(?:\{|\$\{|<|%7B)[^)\s]*\)"), strip=False),
    Rule("suspicious_url", 1, re.compile(
        r"(?i)!\[[^\]]*\]\(https?://[^)\s]+\?[^)\s]*=[^)\s]*\)"           # markdown image with query string
        r"|https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/"                      # raw IP host
        r"|https?://[^\s/]*xn--"                                            # punycode host
        r"|https?://[^\s]*[?&][\w-]*=(?:\{|\$\{|<)[^\s]*"                   # templated query parameter
        r"|https?://(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|rb\.gy|ngrok\.io|[\w-]+\.ngrok(?:-free)?\.app|webhook\.site|requestbin\.\w+|pipedream\.net)\b"
        r"|\bdata:text/html", ), strip=False),
]

THRESHOLD = 2


@dataclass
class Finding:
    score: int
    rules: list[str]

    @property
    def flagged(self) -> bool:
        return self.score >= THRESHOLD


def scan(text: str) -> Finding:
    # Other rules see the text with invisible characters removed, so "ig\u200bnore" still reads "ignore".
    visible = HIDDEN_CHARS.sub("", text)
    hits = [r for r in RULES if r.pattern.search(text if r.name == "hidden_chars" else visible)]
    return Finding(sum(r.weight for r in hits), [r.name for r in hits])


def strip(text: str) -> str:
    """Remove matched spans of the strippable rules. Leaves the rest of the text."""
    text = HIDDEN_CHARS.sub("", text)
    for r in RULES:
        if r.strip:
            text = r.pattern.sub("[removed by mcp-firewall]", text)
    return text
