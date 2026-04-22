"""
Model 4: Wireshark-Inspired Traffic Pattern Analyser
Detects suspicious traffic patterns, protocol anomalies, and data exfiltration indicators.
Mirrors Wireshark's deep packet inspection and protocol dissection approach.
"""

import re
import time


class WiresharkModel:
    """
    Wireshark-inspired model: protocol anomaly and traffic pattern detection.
    Looks for malformed headers, cleartext credential leaks, protocol violations,
    C2 traffic patterns, and data exfiltration signatures in request payloads.
    Confidence: 72-88% (traffic patterns = contextual, not absolute).
    """

    MODEL_NAME = "Wireshark"
    MODEL_TYPE = "Traffic Pattern / Protocol Analyser"

    def __init__(self):
        self.traffic_patterns = {
            "CleartextCredentials": (r"(password=\w+&|passwd=\w+|Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,})", 88),
            "SessionHijack":        (r"(document\.cookie|Set-Cookie:.*session|PHPSESSID=|JSESSIONID=)", 85),
            "ARPSpoofIndicator":    (r"(arp_reply|gratuitous_arp|mac_flood|arp_poison)",                72),
            "DNSExfiltration":      (r"([a-z0-9]{20,}\.(com|net|org|io)\?|dns_tunnel|iodine|dnscat)", 84),
            "ProtocolViolation":    (r"(Content-Length:\s*-\d|Transfer-Encoding.*chunked.*Content-Length|HTTP/\d\.\d\s+[6-9]\d\d)", 80),
            "DataExfiltration":     (r"(base64,[A-Za-z0-9+/]{100,}|multipart/form.*filename=.*\.\.(php|asp|jsp))", 86),
            "MITMIndicator":        (r"(ssl_strip|sslsniff|ettercap|bettercap|arp_spoof)",             90),
            "BeaconingPattern":     (r"(interval=\d+&beacon|heartbeat=|keepalive=\d+&cmd|c2_check)",   83),
        }

    def analyze(self, payload: str) -> dict:
        start = time.perf_counter()
        threats = []

        for pattern_id, (pattern, confidence) in self.traffic_patterns.items():
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                threats.append({
                    "type": pattern_id,
                    "confidence": confidence,
                    "matched": match.group(0)[:60],
                    "reason": f"Traffic anomaly '{pattern_id}' detected",
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
            "rules_checked": len(self.traffic_patterns),
        }
