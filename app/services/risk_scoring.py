"""
Threat Risk Scoring Engine
Factors: malware feeds, URL count, infrastructure reuse, campaign duration
"""
from datetime import datetime
from app.schemas.threat_schema import ThreatLookupResponse


class RiskScoringService:
    """Calculates risk score for domains/infrastructure"""

    @staticmethod
    def _parse_date(s: str | None) -> datetime | None:
        if not s:
            return None
        try:
            return datetime.strptime(s.split()[0], "%Y-%m-%d")
        except (ValueError, IndexError):
            return None

    @staticmethod
    def calculate(response: ThreatLookupResponse) -> dict:
        """
        Calculate risk score 0-100.
        Levels: 0-30 Low, 31-60 Medium, 61-100 High
        """
        score = 0
        factors = []

        url_count = len(response.malicious_urls or [])
        if url_count > 0:
            url_score = min(40, url_count * 5)
            score += url_score
            factors.append({"name": "malicious_urls", "score": url_score, "detail": f"{url_count} URLs"})

        active = sum(1 for u in (response.malicious_urls or []) if u.status == "active")
        if active > 0:
            active_score = min(20, active * 5)
            score += active_score
            factors.append({"name": "active_malware", "score": active_score, "detail": f"{active} active"})

        campaigns = response.campaigns or []
        for c in campaigns:
            first = RiskScoringService._parse_date(c.first_seen)
            last = RiskScoringService._parse_date(c.last_seen)
            if first and last:
                days = (last - first).days
                if days > 30:
                    score += min(15, days // 10)
                    factors.append({"name": "campaign_duration", "score": min(15, days // 10), "detail": f"{days} days"})
                break

        infra = response.infrastructure
        if infra:
            shared = len(infra.shared_hosts or [])
            if shared > 0:
                shared_score = min(15, shared * 3)
                score += shared_score
                factors.append({"name": "shared_infrastructure", "score": shared_score, "detail": f"{shared} hosts"})

        all_domains = set()
        for c in campaigns:
            all_domains.update(c.related_domains or [])
        if len(all_domains) > 5:
            score += min(10, len(all_domains))
            factors.append({"name": "related_domains", "score": min(10, len(all_domains)), "detail": f"{len(all_domains)} domains"})

        score = min(100, score)
        level = "low" if score <= 30 else "medium" if score <= 60 else "high"

        return {
            "domain": response.query,
            "risk_score": score,
            "risk_level": level,
            "factors": factors,
        }
