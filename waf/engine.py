#engine.py

from waf.owasp_detector import OWASPDetector
from waf.behavior_engine import BehaviorEngine
import numpy as np

class SecureEngine:
    def __init__(self):
        self.owasp = OWASPDetector()
        self.behavior = BehaviorEngine()
        self.blocked_ips = set()

    def process(self, request, ip):
        if ip in self.blocked_ips:
            return {"blocked": True, "reason": "IP_BLOCKED"}

        payload = f"{request['method']} {request['url']} {request['body']}"

        owasp_hits = self.owasp.scan(payload)
        behavior_hits = self.behavior.analyze(payload)

        all_threats = owasp_hits + behavior_hits

        if all_threats:
            confidence = np.mean([t["confidence"] for t in all_threats])
            self.blocked_ips.add(ip)

            return {
                "blocked": True,
                "confidence": confidence,
                "threats": all_threats
            }

        return {"blocked": False}
    