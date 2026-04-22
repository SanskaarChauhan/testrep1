"""
Model 1: Burp Suite-Inspired OWASP Web Scanner
Signature-based detection of web application vulnerabilities.
Mirrors Burp Suite's proxy/scanner approach: intercepts and pattern-matches
known OWASP Top 10 attack signatures in HTTP request data.
"""

import re
import time


class BurpSuiteModel:
    """
    Burp Suite-inspired model: deep web-layer signature scanning.
    Covers OWASP Top 10 with high-confidence pattern matching.
    Confidence: 95% on match (deterministic — pattern either matches or not).
    """

    MODEL_NAME = "Burp Suite"
    MODEL_TYPE = "Signature / OWASP Web Scanner"

    def __init__(self):
        # Extended OWASP Top 10 rules — mirrors Burp Suite scanner checks
        self.rules = {
            "A03:SQLi":         (r"(union\s+select|or\s+1=1|--|'\s*or\s*'|drop\s+table|insert\s+into|1\s*=\s*1|xp_cmdshell|sleep\s*\(|benchmark\s*\()", 95),
            "A03:XSS":          (r"(<script[\s>]|javascript:|on\w+\s*=|<iframe|<svg.*onload|alert\s*\(|document\.cookie)", 95),
            "A03:CMDi":         (r"(;|\||&&|`|\$\(|/bin/sh|/bin/bash|cmd\.exe|powershell)", 92),
            "A03:PathTraversal":(r"(\.\./|\.\.\\|%2e%2e%2f|%252e|/etc/passwd|/windows/system32)", 93),
            "A03:XXE":          (r"(<\?xml|<!DOCTYPE|<!ENTITY|SYSTEM\s+[\"']file)", 94),
            "A10:SSRF":         (r"(localhost|127\.0\.\d+\.\d+|169\.254\.|file://|dict://|gopher://|0x7f)", 91),
            "A08:Deserial":     (r"(O:\d+:|rO0AB|__sleep|__wakeup|unserialize\s*\(|java\.io\.)", 93),
            "A02:WeakCrypto":   (r"(md5\s*\(|sha1\s*\(|des\s+encrypt|rc4|base64_decode\s*\(eval)", 88),
            "A01:BrokenAccess": (r"(../admin|/etc/shadow|/proc/self|\.git/config|\.env\b|wp-config)", 90),
            "A07:BrokenAuth":   (r"(admin:admin|root:root|password=123|pass=admin|login=test|admin=1)", 89),
        }

    def scan(self, payload: str) -> dict:
        start = time.perf_counter()
        threats = []

        for rule_id, (pattern, confidence) in self.rules.items():
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                threats.append({
                    "type": rule_id,
                    "confidence": confidence,
                    "matched": match.group(0)[:60],
                    "reason": f"OWASP rule {rule_id} matched pattern in payload",
                    "model": self.MODEL_NAME,
                })

        elapsed_ms = (time.perf_counter() - start) * 1000

        return {
            "model": self.MODEL_NAME,
            "model_type": self.MODEL_TYPE,
            "threats": threats,
            "blocked": len(threats) > 0,
            "confidence": max((t["confidence"] for t in threats), default=0),
            "threat_count": len(threats),
            "scan_time_ms": round(elapsed_ms, 3),
            "rules_checked": len(self.rules),
        }
