"""
Scan engine - orchestrates OSINT investigation
"""
from app.engine.module_runner import ModuleRunner
from app.engine.scan_context import ScanContext
from app.modules.module_loader import load_all_modules
from app.services.campaign_analyzer import CampaignAnalyzer
from app.clients.urlhaus_client import URLHausClient
from app.graph.graph_service import GraphService
from app.services.timeline_analyzer import TimelineAnalyzer
from app.services.risk_scoring import RiskScoringService
from app.services.intel_correlator import IntelCorrelator
from app.schemas.threat_schema import ThreatLookupResponse


class ScanEngine:
    """Orchestrates full threat intelligence investigation"""

    def __init__(self, urlhaus_key: str, github_token: str | None = None):
        self.modules = load_all_modules(urlhaus_key, github_token)
        self.runner = ModuleRunner(self.modules)
        self.client = URLHausClient(urlhaus_key)
        self.analyzer = CampaignAnalyzer(self.client)

    async def investigate(self, target: str, module_names: list[str] | None = None) -> dict:
        """
        Run full investigation:
        1. Execute OSINT modules
        2. Get URLHaus threat data
        3. Build graph
        4. Build timeline
        5. Calculate risk score
        6. Correlate intelligence
        """
        # Run modules
        ctx = await self.runner.run_all(target, module_names)

        # Get threat lookup (URLHaus) for graph, timeline, risk
        try:
            lookup = await self.analyzer.analyze_domain(target)
        except Exception:
            lookup = ThreatLookupResponse(query=target, query_type="domain")

        graph = GraphService.build_from_lookup(lookup)
        timeline = TimelineAnalyzer.analyze(lookup)
        risk = RiskScoringService.calculate(lookup)
        correlation = IntelCorrelator.correlate(lookup)

        # Aggregate module results
        module_data = {}
        for name, result in ctx.module_results.items():
            module_data[name] = {
                "source": result.source,
                "success": result.meta.get("success", False),
                "data": result.data,
            }

        return {
            "target": target,
            "threat_lookup": lookup.model_dump(),
            "graph": graph.to_d3(),
            "timeline": timeline,
            "risk": risk,
            "correlation": correlation,
            "module_results": module_data,
            "errors": ctx.errors,
        }
