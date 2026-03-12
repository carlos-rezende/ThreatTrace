"""
Graph builder - constructs threat infrastructure graph from intelligence data
"""
from urllib.parse import urlparse
from collections import defaultdict

from app.graph.graph_models import GraphNode, GraphEdge, ThreatInfrastructureGraph
from app.schemas.threat_schema import ThreatLookupResponse, MaliciousURL, CampaignInfo


def _extract_host(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path.split("/")[0]
        return host.split(":")[0].strip().lower() if host else ""
    except Exception:
        return ""


def _normalize_id(prefix: str, value: str, max_len: int = 64) -> str:
    safe = value.replace(":", "_").replace("/", "_")[:max_len]
    return f"{prefix}:{safe}"


def build_graph(response: ThreatLookupResponse) -> ThreatInfrastructureGraph:
    """
    Build threat infrastructure graph from lookup response.
    
    Relationships:
    - Domain → Malicious URL (hosts)
    - URL → Payload Hash (serves)
    - Domain → IP (resolves_to)
    - Domain → Related Domain (related_to)
    - Domain → Malware Family (associated_with)
    """
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    seen_nodes: set[str] = set()
    edge_id = 0

    def add_node(node_id: str, node_type: str, label: str, metadata: dict | None = None):
        if node_id not in seen_nodes:
            nodes.append(GraphNode(
                id=node_id,
                type=node_type,
                label=label,
                metadata=metadata or {},
                group=node_type,
            ))
            seen_nodes.add(node_id)

    def add_edge(source: str, target: str, relation: str):
        nonlocal edge_id
        eid = f"e{edge_id}"
        edge_id += 1
        edges.append(GraphEdge(id=eid, source=source, target=target, relation=relation))

    root_id = _normalize_id("domain", response.query)
    add_node(root_id, "domain", response.query, {"query_type": response.query_type, "is_root": True})
    graph = ThreatInfrastructureGraph(root_id=root_id)

    # Domain → Malicious URL → Payload Hash
    for url_data in response.malicious_urls or []:
        url_id = _normalize_id("url", url_data.url, 80)
        add_node(url_id, "url", url_data.url[:80] + ("..." if len(url_data.url) > 80 else ""), {
            "status": url_data.status,
            "family": url_data.malware_family,
            "first_seen": url_data.first_seen,
        })
        add_edge(root_id, url_id, "hosts")

        if url_data.payload_hash:
            hash_id = _normalize_id("hash", url_data.payload_hash[:32])
            add_node(hash_id, "payload_hash", url_data.payload_hash[:16] + "...", {
                "family": url_data.malware_family,
            })
            add_edge(url_id, hash_id, "serves")

    # Domain → Related Domains (from campaigns)
    for campaign in response.campaigns or []:
        for domain in campaign.related_domains or []:
            if domain != response.query:
                domain_id = _normalize_id("domain", domain)
                add_node(domain_id, "domain", domain, {"family": campaign.family})
                add_edge(root_id, domain_id, "related_to")

    # Domain → IPs
    if response.infrastructure:
        for ip in response.infrastructure.ips or []:
            ip_id = _normalize_id("ip", ip)
            add_node(ip_id, "ip", ip, {})
            add_edge(root_id, ip_id, "resolves_to")

    graph.nodes = nodes
    graph.edges = edges
    return graph
