#behaviour_engine
import re

class BehaviorEngine :
    def __init__(self):
        self.patterns = {
            "scanner": r"(sqlmap|nikto|dirb)",
            "encoding": r"(%25|%u|&#x)",
            "repetition": r"(.{1,10})\1{5,}"
        }

    def analyze(self, payload):
        anomalies = []
        for name, pattern in self.patterns.items():
            if re.search(pattern, payload, re.IGNORECASE):
                anomalies.append({"type": name, "confidence": 85})
        return anomalies
    