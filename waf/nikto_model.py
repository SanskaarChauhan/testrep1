"""
Model 5: Nikto-Inspired Web Server Vulnerability Scanner
Detects server misconfigurations, exposed files, outdated software indicators,
and default credential patterns. Mirrors Nikto's fast server-level audit approach.
"""

import re
import time


class NiktoModel:
    """
    Nikto-inspired model: web server misconfiguration and exposure detection.
    Fast, broad scanning for known bad configurations, exposed sensitive paths,
    default installations, and server-level vulnerability indicators.
    Confidence: 75-92% (some misconfigs are definitive, others contextual).
    """

    MODEL_NAME = "Nikto"
    MODEL_TYPE = "Web Server Misconfiguration Scanner"

    def __init__(self):
        self.server_patterns = {
            "ExposedSensitivePath":  (r"(/\.env|/\.git/|/\.htaccess|/web\.config|/wp-config\.php|/config\.php|/database\.yml)", 92),
            "DefaultAdminPanel":     (r"(/admin|/administrator|/phpmyadmin|/wp-admin|/cpanel|/manager/html)", 78),
            "OutdatedSoftware":      (r"(Apache/[12]\.\d|PHP/[45]\.\d|OpenSSL/[01]\.\d|nginx/[01]\.\d)", 85),
            "DirectoryListing":      (r"(Index of /|Directory listing|Parent Directory.*href|<title>Index)", 90),
            "DefaultCredentials":    (r"(admin/admin|tomcat/tomcat|admin/password|test/test|guest/guest)", 88),
            "ServerInfoLeakage":     (r"(X-Powered-By:|Server:\s*(Apache|IIS|nginx)|X-AspNet-Version:)", 80),
            "BackupFileExposed":     (r"(\.(bak|old|backup|orig|temp|tmp|swp)$|~$|\.sql$|dump\.sql)", 87),
            "InsecureHTTPMethod":    (r"(^(PUT|DELETE|TRACE|CONNECT|PATCH)\s|Allow:.*TRACE|Allow:.*DELETE)", 83),
            "CGIVulnerability":      (r"(/cgi-bin/|/cgi/|shellshock|/bin/bash\s*-c|CGI/1\.[01])",         86),
            "SSLMisconfiguration":   (r"(SSLv2|SSLv3|TLSv1\.0|RC4|DES|EXPORT|NULL cipher)",              82),
        }

    def scan(self, payload: str) -> dict:
        start = time.perf_counter()
        threats = []

        for pattern_id, (pattern, confidence) in self.server_patterns.items():
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                threats.append({
                    "type": pattern_id,
                    "confidence": confidence,
                    "matched": match.group(0)[:60],
                    "reason": f"Server misconfiguration '{pattern_id}' detected",
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
            "rules_checked": len(self.server_patterns),
        }
