"""
Intelligence Correlation Engine
Correlates: shared IPs, payload hashes, malware families, domain patterns
"""
from collections import defaultdict
from app.schemas.threat_schema import ThreatLookupResponse


class IntelCorrelator:
    """Correlates intelligence between entities"""

    @staticmethod
    def correlate(response: ThreatLookupResponse) -> dict:
        """Extract correlations from threat lookup"""
        related_domains = set()
        shared_infrastructure = []
        shared_payloads = []
        shared_families = defaultdict(list)

        for campaign in response.campaigns or []:
            for d in campaign.related_domains or []:
                if d != response.query:
                    related_domains.add(d)
            shared_families[campaign.family].extend(campaign.related_domains or [])

        if response.infrastructure:
            shared_infrastructure = list(response.infrastructure.shared_hosts or [])
            shared_infrastructure.extend(response.infrastructure.domains or [])

        for campaign in response.campaigns or []:
            for h in campaign.payload_hashes or []:
                shared_payloads.append({"hash": h[:32] + "...", "family": campaign.family})

        return {
            "related_domains": sorted(related_domains),
            "shared_infrastructure": shared_infrastructure[:50],
            "shared_payloads": shared_payloads[:20],
            "malware_families": dict(shared_families),
        }
