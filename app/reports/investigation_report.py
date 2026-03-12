"""
Full Investigation Report - JSON, PDF, Markdown
Includes: infrastructure, risk score, campaigns, timeline, graph summary, correlations
"""
import json
from datetime import datetime
from typing import Any
from app.schemas.threat_schema import ThreatLookupResponse


class InvestigationReport:
    """Generates comprehensive investigation reports"""

    @staticmethod
    def to_json(investigation: dict) -> str:
        """Full investigation as JSON"""
        return json.dumps(investigation, indent=2, ensure_ascii=False)

    @staticmethod
    def to_markdown(data: dict) -> str:
        """
        Generate Markdown report from investigation or lookup data.
        Accepts: full investigation dict, or ThreatLookupResponse-like dict.
        """
        target = data.get("target") or data.get("query", "unknown")
        lookup = data.get("threat_lookup") or data
        risk = data.get("risk", {})
        timeline = data.get("timeline", {})
        corr = data.get("correlation", {})

        lines = [
            "# ThreatTrace Investigation Report",
            f"**Target:** {target}",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "## Risk Assessment",
            f"- **Score:** {risk.get('risk_score', 0)}/100",
            f"- **Level:** {risk.get('risk_level', 'unknown')}",
            "",
            "## Malicious URLs",
        ]
        urls = lookup.get("malicious_urls", [])
        for u in urls[:20]:
            lines.append(f"- `{u.get('url', '')}` | {u.get('malware_family', '-')} | {u.get('status', '-')}")
        if not urls:
            lines.append("- None found")
        lines.append("")

        lines.append("## Campaigns")
        campaigns = timeline.get("campaigns") or lookup.get("campaigns", [])
        for c in campaigns:
            lines.append(f"- **{c.get('family', '')}**: {c.get('first_seen', '')} - {c.get('last_seen', '')} ({c.get('activity_days', 0)} days)")
        if not campaigns:
            lines.append("- None detected")
        lines.append("")

        lines.append("## Infrastructure")
        infra = lookup.get("infrastructure", {})
        if infra:
            if infra.get("domains"):
                lines.append(f"- **Domains:** {', '.join(infra['domains'][:15])}")
            if infra.get("ips"):
                lines.append(f"- **IPs:** {', '.join(infra['ips'][:15])}")
        else:
            lines.append("- None discovered")
        lines.append("")

        lines.append("## Correlations")
        lines.append(f"- Related domains: {len(corr.get('related_domains', []))}")
        lines.append(f"- Shared infrastructure: {len(corr.get('shared_infrastructure', []))}")

        return "\n".join(lines)
