#owasp_detector.py
import re

class OWASPDetector :
    def __init__(self):
        self.rules = {
            "SQLI": r"(union\s+select|or\s+1=1|--)",
            "XSS": r"(<script|javascript:|on\w+=)",
            "CMD": r"(;|&&|\||/bin/)",
            "PATH": r"(\.\./|\.\.\\)"
        }

    def scan(self, payload):
        threats = []
        for name, pattern in self.rules.items():
            if re.search(pattern, payload, re.IGNORECASE):
                threats.append({"type": name, "confidence": 95})
        return threats
    