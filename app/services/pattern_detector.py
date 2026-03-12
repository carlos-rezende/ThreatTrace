"""
Threat Actor Pattern Detection
Detects: fast flux, DGA indicators, infrastructure reuse
"""
import re
from app.schemas.threat_schema import ThreatLookupResponse


class PatternDetector:
    """Detects suspicious infrastructure patterns"""

    # DGA-like: random character subdomains
    DGA_PATTERN = re.compile(r"^[a-z0-9]{8,20}\.[a-z0-9]{8,20}\.", re.I)

    @staticmethod
    def detect(response: ThreatLookupResponse) -> dict:
        """Analyze patterns in threat data"""
        patterns = []
        score = 0

        # Infrastructure reuse
        infra = response.infrastructure
        if infra and (infra.shared_hosts or infra.domains):
            shared_count = len(infra.shared_hosts or []) + len(infra.domains or [])
            if shared_count > 3:
                patterns.append({
                    "type": "infrastructure_reuse",
                    "description": f"{shared_count} shared hosts/domains - possible bulletproof hosting",
                    "confidence": "medium",
                })
                score += 30

        # Multiple campaigns
        campaigns = response.campaigns or []
        if len(campaigns) > 2:
            patterns.append({
                "type": "multi_campaign",
                "description": f"Domain associated with {len(campaigns)} malware families",
                "confidence": "high",
            })
            score += 25

        # High URL count
        url_count = len(response.malicious_urls or [])
        if url_count > 10:
            patterns.append({
                "type": "high_volume",
                "description": f"{url_count} malicious URLs - possible distribution hub",
                "confidence": "high",
            })
            score += 20

        # Check domain for DGA-like patterns
        domain = response.query
        if PatternDetector.DGA_PATTERN.match(domain):
            patterns.append({
                "type": "dga_indicator",
                "description": "Domain matches DGA-like pattern (random subdomain)",
                "confidence": "low",
            })
            score += 15

        return {
            "domain": domain,
            "patterns": patterns,
            "suspicion_score": min(100, score),
        }
