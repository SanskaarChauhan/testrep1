"""
Model 3: Nmap-Inspired Network Reconnaissance Detector
Detects network scanning, port probing, and service enumeration patterns.
Mirrors Nmap's approach of fingerprinting services and identifying open attack surfaces.
"""

import re
import time


class NmapModel:
    """
    Nmap-inspired model: detects network reconnaissance and service probing patterns.
    Looks for port scan indicators, service version probing, OS fingerprinting
    payloads, and network discovery patterns embedded in HTTP requests.
    Confidence: 80-88% (network patterns in HTTP = indirect indicator).
    """

    MODEL_NAME = "Nmap"
    MODEL_TYPE = "Network Reconnaissance Detector"

    def __init__(self):
        self.recon_patterns = {
            "PortScanIndicator":    (r"(port=\d{1,5}|:\d{2,5}/tcp|:\d{2,5}/udp|scan_port|open_port)", 82),
            "ServiceProbe":         (r"(SSH-2\.0|HTTP/1\.[01]\s+\d|SMTP\s+\d{3}|FTP\s+\d{3}|banner_grab)", 84),
            "OSFingerprint":        (r"(TTL=\d+|Window\s+Size|MSS=\d+|tcp_options|os_detect)", 80),
            "NetworkDiscovery":     (r"(arp_scan|ping_sweep|traceroute|host_discovery|netdiscover)", 86),
            "ServiceEnumeration":   (r"(enum4linux|smbclient|snmpwalk|ldapsearch|rpcclient)", 88),
            "VersionDetection":     (r"(-sV|-sC|-A\s|--script=|nmap\s+-)",                  90),
            "FirewallEvasion":      (r"(-f\s|--mtu|--data-length|--source-port|decoy.*scan)", 85),
            "VulnScriptCheck":      (r"(vuln\.nse|smb-vuln|http-shellshock|ftp-anon|ssl-heartbleed)", 88),
        }

    def scan(self, payload: str) -> dict:
        start = time.perf_counter()
        threats = []

        for pattern_id, (pattern, confidence) in self.recon_patterns.items():
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                threats.append({
                    "type": pattern_id,
                    "confidence": confidence,
                    "matched": match.group(0)[:60],
                    "reason": f"Network recon pattern '{pattern_id}' found",
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
            "rules_checked": len(self.recon_patterns),
        }
