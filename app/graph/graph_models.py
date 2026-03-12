"""
Graph models for Threat Infrastructure - D3.js / Cytoscape.js compatible
"""
from typing import Optional, Any
from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    """Node in threat infrastructure graph"""
    id: str
    type: str  # domain, url, payload_hash, ip, malware_family
    label: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    group: Optional[str] = None  # For D3.js grouping


class GraphEdge(BaseModel):
    """Edge representing relationship between entities"""
    id: Optional[str] = None
    source: str
    target: str
    relation: str  # hosts, serves, related_to, resolves_to, shares_infrastructure
    metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatInfrastructureGraph(BaseModel):
    """Complete threat infrastructure graph - D3.js/Cytoscape compatible"""
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    root_id: Optional[str] = None

    def to_cytoscape(self) -> dict:
        """Format for Cytoscape.js"""
        return {
            "elements": {
                "nodes": [
                    {"data": {"id": n.id, "label": n.label, "type": n.type, **n.metadata}}
                    for n in self.nodes
                ],
                "edges": [
                    {
                        "data": {
                            "id": e.id or f"{e.source}-{e.target}-{e.relation}",
                            "source": e.source,
                            "target": e.target,
                            "relation": e.relation,
                        }
                    }
                    for e in self.edges
                ],
            },
            "root_id": self.root_id,
        }

    def to_d3(self) -> dict:
        """Format for D3.js force-directed graph"""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "type": n.type,
                    "group": n.type,
                    **n.metadata,
                }
                for n in self.nodes
            ],
            "links": [
                {
                    "source": e.source,
                    "target": e.target,
                    "relation": e.relation,
                }
                for e in self.edges
            ],
            "root_id": self.root_id,
        }

    def to_dict(self) -> dict:
        """Generic JSON export"""
        return {
            "nodes": [n.model_dump() for n in self.nodes],
            "edges": [e.model_dump() for e in self.edges],
            "root_id": self.root_id,
        }
