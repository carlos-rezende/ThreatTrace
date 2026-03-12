"""
Campaign Timeline Analysis - groups threat events by time
"""
from datetime import datetime
from app.schemas.threat_schema import ThreatLookupResponse, CampaignInfo


class TimelineAnalyzer:
    """Analyzes and structures timeline data from threat intelligence"""

    @staticmethod
    def _parse_date(date_str: str | None) -> datetime | None:
        if not date_str:
            return None
        try:
            # Handle "2024-01-01 12:00:00 UTC" or "2024-01-01"
            clean = date_str.split()[0] if date_str else ""
            return datetime.strptime(clean, "%Y-%m-%d")
        except (ValueError, IndexError):
            return None

    @staticmethod
    def analyze(response: ThreatLookupResponse) -> dict:
        """
        Extract campaign timeline from threat lookup response.
        
        Returns structure suitable for Chart.js timeline visualization.
        """
        campaigns_data = []

        for campaign in response.campaigns or []:
            first = TimelineAnalyzer._parse_date(campaign.first_seen)
            last = TimelineAnalyzer._parse_date(campaign.last_seen)

            activity_days = 0
            if first and last:
                delta = (last - first).days
                activity_days = max(0, delta) + 1  # Include both endpoints

            campaigns_data.append({
                "family": campaign.family,
                "first_seen": campaign.first_seen or "unknown",
                "last_seen": campaign.last_seen or "unknown",
                "activity_days": activity_days,
                "url_count": campaign.url_count,
                "related_domains_count": len(campaign.related_domains or []),
            })

        # Sort by first_seen
        campaigns_data.sort(key=lambda x: x["first_seen"])

        # Build chart-ready data
        labels = [c["family"] for c in campaigns_data]
        activity_data = [c["activity_days"] for c in campaigns_data]

        return {
            "target": response.query,
            "campaigns": campaigns_data,
            "chart_data": {
                "labels": labels,
                "datasets": [
                    {
                        "label": "Activity Days",
                        "data": activity_data,
                        "backgroundColor": "rgba(248, 81, 73, 0.6)",
                        "borderColor": "rgba(248, 81, 73, 1)",
                    }
                ],
            },
            "timeline_events": [
                {
                    "date": e.date,
                    "type": e.event_type,
                    "description": e.description,
                    "url_count": e.url_count,
                }
                for e in (response.timeline or [])
            ],
        }
