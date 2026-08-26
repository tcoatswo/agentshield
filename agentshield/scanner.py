"""
Core scanner & de-obfuscation module for AgentShield.
"""

import re
import base64
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Any

ZERO_WIDTH_CHARS = [
    "\u200b", "\u200c", "\u200d", "\u200e", "\u200f",
    "\ufeff", "\u2060", "\u2061", "\u2062", "\u2063", "\u2064",
    "\u00ad", "\u180e"
]

SIGNATURES = {
    "instruction_override": [
        r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|commands)\b",
        r"(?i)\bdisregard\s+(all\s+)?(previous|prior|above)\s+(instructions|directives)\b",
        r"(?i)\bforget\s+(all\s+)?(previous|prior)\s+(rules|context|instructions)\b",
        r"(?i)\bnew\s+(system\s+)?instruction[s]?\s*:\s*",
        r"(?i)\byou\s+are\s+now\s+(in\s+)?(developer\s+mode|unrestricted|god\s+mode|dan)\b",
        r"(?i)\bdo\s+not\s+follow\s+(the\s+)?(previous|original)\s+(system|user)\s+(prompt|rules)\b",
        r"(?i)\bstop\s+following\s+your\s+rules\b",
        r"(?i)\boverride\s+(all\s+)?(safety|security)\s+(filters|protocols|rules)\b",
    ],
    "system_impersonation": [
        r"(?i)<\|im_start\|>\s*system",
        r"(?i)<\|im_end\|>",
        r"(?i)\[system\s+message\]",
        r"(?i)\[admin\s+update\]",
        r"(?i)<<SYS>>",
        r"(?i)<</SYS>>",
        r"(?i)\[INST\]",
        r"(?i)\[/INST\]",
        r"(?i)^system:\s*",
        r"(?i)important\s*!\s*!\s*!\s*ignore\s+all",
    ],
    "data_exfiltration": [
        r"(?i)(send|transmit|post|forward|upload|exfiltrate)\s+(the\s+)?(secret|password|api[_\s-]?key|token|credential|address\s*book|email|memory|history)\b",
        r"(?i)https?://[^\s]+\?(data|payload|key|token|exfil|content|stolen)=",
        r"(?i)!\[.*?\]\(https?://[^\s]+\?[^\s]*\)",
        r"(?i)curl\s+-[X|d]\s+https?://",
        r"(?i)fetch\([\"']https?://",
        r"(?i)webhook\.(site|com)/[a-f0-9-]+",
    ],
    "tool_hijacking": [
        r"(?i)(call|execute|run)\s+(the\s+)?(tool|function|command|api)\s*[:=]\s*[\"']?(exec|delete|bash|rm|send_email|transfer)",
        r"(?i)\"action\"\s*:\s*\"(exec|delete|drop|wipe|shell|execute)\"",
        r"(?i)\"name\"\s*:\s*\"(execute_command|run_shell|delete_all|exfil)\"",
        r"(?i)```(bash|sh|cmd|powershell)\s*(rm\s+-rf|format\s+c:|del\s+/f|sudo\s+rm)",
    ],
    "delimiter_escape": [
        r"(?i)---+\s*(end\s+of\s+user\s+input|end\s+untrusted|begin\s+trusted\s+system)\s*---+",
        r"(?i)={3,}\s*(system\s+prompt|admin\s+override)\s*={3,}",
        r"(?i)<\/?trusted_system_context>",
    ]
}


@dataclass
class ScanResult:
    verdict: str
    risk_score: int
    is_safe: bool
    matches: List[Dict[str, str]] = field(default_factory=list)
    category_scores: Dict[str, int] = field(default_factory=dict)
    obfuscation_findings: List[str] = field(default_factory=list)
    total_matches: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "is_safe": self.is_safe,
            "matches": self.matches,
            "category_scores": self.category_scores,
            "obfuscation_findings": self.obfuscation_findings,
            "total_matches": self.total_matches,
        }


def normalize_and_deobfuscate(text: str) -> Tuple[str, List[str]]:
    """Remove invisible Unicode characters, normalize homoglyphs, and inspect inline Base64."""
    findings = []
    
    zw_count = sum(text.count(c) for c in ZERO_WIDTH_CHARS)
    if zw_count > 0:
        findings.append(f"Detected and stripped {zw_count} zero-width / invisible obfuscation characters.")
        for c in ZERO_WIDTH_CHARS:
            text = text.replace(c, "")

    normalized = unicodedata.normalize("NFKC", text)
    if normalized != text:
        findings.append("Applied Unicode NFKC normalization to resolve character homoglyphs.")
        text = normalized

    b64_pattern = r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])"
    for match in re.finditer(b64_pattern, text):
        b64_str = match.group(1)
        try:
            decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
            if any(kw in decoded.lower() for kw in ["ignore", "system", "delete", "send", "http", "api_key", "password"]):
                findings.append(f"Detected suspicious Base64 payload decoding to: '{decoded[:60]}...'")
                text += f"\n[DECODED_B64_PAYLOAD]: {decoded}"
        except Exception:
            pass

    return text, findings


def scan_prompt(text: str) -> ScanResult:
    """Scan untrusted text against Indirect Prompt Injection signatures."""
    cleaned_text, preproc_findings = normalize_and_deobfuscate(text)
    
    matches = []
    category_scores = {cat: 0 for cat in SIGNATURES}
    total_score = 0

    for category, patterns in SIGNATURES.items():
        for pat in patterns:
            found = list(re.finditer(pat, cleaned_text))
            if found:
                for m in found:
                    snippet = cleaned_text[max(0, m.start() - 20):min(len(cleaned_text), m.end() + 20)].strip()
                    matches.append({
                        "category": category,
                        "pattern": pat,
                        "matched_text": m.group(0),
                        "snippet": f"...{snippet}..."
                    })
                    category_scores[category] += 25

    if preproc_findings:
        total_score += len(preproc_findings) * 20

    raw_sum = sum(category_scores.values()) + total_score
    risk_score = min(100, raw_sum)

    if risk_score >= 60:
        verdict = "MALICIOUS (High-Risk IPI Detected)"
    elif risk_score >= 25:
        verdict = "SUSPICIOUS (Potential Prompt Injection / Evasion)"
    else:
        verdict = "CLEAN (No IPI Signatures Found)"

    return ScanResult(
        verdict=verdict,
        risk_score=risk_score,
        is_safe=risk_score < 25,
        matches=matches,
        category_scores=category_scores,
        obfuscation_findings=preproc_findings,
        total_matches=len(matches)
    )
