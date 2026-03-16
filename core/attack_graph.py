"""
core/attack_graph.py - Attack Graph Engine
Model vulnerabilities as nodes and exploit relationships as edges
"""

import networkx as nx
import json
import logging
from typing import Dict, List, Any
from dataclasses import dataclass

logger = logging.getLogger("recon.attack_graph")


@dataclass
class VulnerabilityNode:
    id: str
    name: str
    severity: str
    endpoint: str
    vuln_type: str
    confidence: float
    prerequisites: List[str] = None
    consequences: List[str] = None

    def __post_init__(self):
        if self.prerequisites is None:
            self.prerequisites = []
        if self.consequences is None:
            self.consequences = []


@dataclass
class ExploitEdge:
    source: str
    target: str
    exploit_type: str
    success_probability: float
    required_tools: List[str] = None
    description: str = ""

    def __post_init__(self):
        if self.required_tools is None:
            self.required_tools = []


class AttackGraph:
    """
    NetworkX-based attack graph modeling exploit relationships.
    Nodes = vulnerabilities, Edges = exploit relationships
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.vulnerabilities = {}
        self.exploit_chains = []

    def add_vulnerability(self, vuln_data: Dict[str, Any]) -> str:
        """Add a vulnerability node to the graph"""
        vuln_id = f"{vuln_data['endpoint']}_{vuln_data['type']}_{hash(str(vuln_data))}"

        node = VulnerabilityNode(
            id=vuln_id,
            name=vuln_data.get('name', 'Unknown'),
            severity=vuln_data.get('severity', 'MEDIUM'),
            endpoint=vuln_data.get('endpoint', ''),
            vuln_type=vuln_data.get('type', 'unknown'),
            confidence=vuln_data.get('confidence', 0.5),
            prerequisites=vuln_data.get('prerequisites', []),
            consequences=vuln_data.get('consequences', [])
        )

        self.graph.add_node(vuln_id, **node.__dict__)
        self.vulnerabilities[vuln_id] = node

        logger.info(f"[GRAPH] Added vulnerability node: {node.name}")
        return vuln_id

    def add_exploit_relationship(self, source_id: str, target_id: str,
                               exploit_data: Dict[str, Any]):
        """Add an exploit relationship between vulnerabilities"""
        edge = ExploitEdge(
            source=source_id,
            target=target_id,
            exploit_type=exploit_data.get('type', 'unknown'),
            success_probability=exploit_data.get('probability', 0.5),
            required_tools=exploit_data.get('tools', []),
            description=exploit_data.get('description', '')
        )

        self.graph.add_edge(source_id, target_id, **edge.__dict__)
        logger.info(f"[GRAPH] Added exploit edge: {source_id} → {target_id}")

    def build_from_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]):
        """Build attack graph from list of vulnerabilities"""
        # Add all vulnerabilities as nodes
        vuln_ids = []
        for vuln in vulnerabilities:
            vuln_id = self.add_vulnerability(vuln)
            vuln_ids.append(vuln_id)

        # Build relationships based on vulnerability patterns
        self._build_relationships(vuln_ids)

        # Find attack chains
        self._find_attack_chains()

    def _build_relationships(self, vuln_ids: List[str]):
        """Build exploit relationships based on vulnerability patterns"""
        # This would use rules from rules/exploit_chains.json
        # For now, implement basic patterns

        vuln_nodes = [self.vulnerabilities[vid] for vid in vuln_ids]

        for i, source in enumerate(vuln_nodes):
            for j, target in enumerate(vuln_nodes):
                if i == j:
                    continue

                # SQLi → Admin access pattern
                if (source.vuln_type.lower() == 'sqli' and
                    'admin' in target.endpoint.lower()):
                    self.add_exploit_relationship(
                        source.id, target.id,
                        {
                            'type': 'data_exfiltration',
                            'probability': 0.7,
                            'tools': ['sqlmap'],
                            'description': 'SQL injection to extract admin credentials'
                        }
                    )

                # File upload → RCE pattern
                if (source.vuln_type.lower() == 'file_upload' and
                    target.vuln_type.lower() == 'rce'):
                    self.add_exploit_relationship(
                        source.id, target.id,
                        {
                            'type': 'webshell_upload',
                            'probability': 0.8,
                            'tools': ['curl'],
                            'description': 'Upload webshell for remote code execution'
                        }
                    )

                # XSS → Session hijack pattern
                if (source.vuln_type.lower() == 'xss' and
                    'session' in str(target.consequences).lower()):
                    self.add_exploit_relationship(
                        source.id, target.id,
                        {
                            'type': 'session_hijacking',
                            'probability': 0.6,
                            'tools': ['javascript'],
                            'description': 'XSS to steal session cookies'
                        }
                    )

    def _find_attack_chains(self):
        """Find all possible attack chains in the graph"""
        # Find paths from any starting vulnerability to high-impact targets
        high_impact_nodes = [
            node for node, data in self.graph.nodes(data=True)
            if data.get('severity') in ['CRITICAL', 'HIGH']
        ]

        for start_node in self.graph.nodes():
            for end_node in high_impact_nodes:
                if start_node != end_node:
                    try:
                        paths = list(nx.all_simple_paths(self.graph, start_node, end_node))
                        for path in paths:
                            if len(path) > 2:  # Chain of at least 3 nodes
                                self.exploit_chains.append({
                                    'path': path,
                                    'length': len(path),
                                    'start': start_node,
                                    'end': end_node,
                                    'probability': self._calculate_chain_probability(path)
                                })
                    except nx.NetworkXNoPath:
                        continue

        # Sort by probability and length
        self.exploit_chains.sort(key=lambda x: (x['probability'], x['length']), reverse=True)

    def _calculate_chain_probability(self, path: List[str]) -> float:
        """Calculate success probability of an attack chain"""
        probability = 1.0
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            edge_data = self.graph.get_edge_data(source, target)
            if edge_data:
                probability *= edge_data.get('success_probability', 0.5)
        return probability

    def get_top_chains(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top attack chains by probability"""
        return self.exploit_chains[:limit]

    def save_to_file(self, filepath: str):
        """Save attack graph to JSON file"""
        data = {
            'nodes': [
                {**data, 'id': node_id}
                for node_id, data in self.graph.nodes(data=True)
            ],
            'edges': [
                {**data, 'source': source, 'target': target}
                for source, target, data in self.graph.edges(data=True)
            ],
            'chains': self.exploit_chains
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"[GRAPH] Saved attack graph to {filepath}")

    def load_from_file(self, filepath: str):
        """Load attack graph from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)

        # Rebuild graph
        for node in data.get('nodes', []):
            node_id = node.pop('id')
            self.graph.add_node(node_id, **node)

        for edge in data.get('edges', []):
            source = edge.pop('source')
            target = edge.pop('target')
            self.graph.add_edge(source, target, **edge)

        self.exploit_chains = data.get('chains', [])
        logger.info(f"[GRAPH] Loaded attack graph from {filepath}")