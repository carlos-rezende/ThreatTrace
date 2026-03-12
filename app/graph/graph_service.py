"""
Graph service - orchestrates graph building and retrieval
"""
from app.graph.graph_builder import build_graph
from app.graph.graph_models import ThreatInfrastructureGraph
from app.schemas.threat_schema import ThreatLookupResponse


class GraphService:
    """Service for threat infrastructure graph operations"""

    @staticmethod
    def build_from_lookup(response: ThreatLookupResponse) -> ThreatInfrastructureGraph:
        """Build graph from threat lookup response"""
        return build_graph(response)

    @staticmethod
    def to_cytoscape(graph: ThreatInfrastructureGraph) -> dict:
        """Export graph for Cytoscape.js"""
        return graph.to_cytoscape()

    @staticmethod
    def to_d3(graph: ThreatInfrastructureGraph) -> dict:
        """Export graph for D3.js"""
        return graph.to_d3()
