"""
core/attack_graph.py - Attack Graph Engine
Model vulnerabilities as nodes and exploit relationships as edges
"""

import networkx as nx
import json
import logging
from typing import Dict, List, Any, Optional
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
    
    Includes state tracking to avoid re-adding similar endpoints.
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.vulnerabilities = {}
        self.exploit_chains = []
        
        # ─── STATE TRACKING FOR DEDUPLICATION ─────────────────────────────────────
        # Track already-added endpoint types to avoid redundancy
        self._added_endpoint_types = set()  # Set of (host, path_base, vuln_type) tuples
        self._endpoint_type_counts = {}     # endpoint_type -> count of added nodes
        self._similarity_threshold = 0.8    # Threshold for considering endpoints similar

    def add_vulnerability(self, vuln_data: Dict[str, Any]) -> str:
        """Add a vulnerability node to the graph"""
        # Use safe dictionary access to prevent KeyError
        endpoint = vuln_data.get('endpoint', 'unknown_endpoint')
        vuln_type = vuln_data.get('type', 'unknown_type')
        vuln_id = f"{endpoint}_{vuln_type}_{hash(str(vuln_data))}"

        node = VulnerabilityNode(
            id=vuln_id,
            name=vuln_data.get('name', 'Unknown'),
            severity=vuln_data.get('severity', 'MEDIUM'),
            endpoint=endpoint,
            vuln_type=vuln_type,
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

    # ─── DEDUPLICATION METHODS ──────────────────────────────────────────────────────

    def _normalize_endpoint(self, endpoint: str) -> str:
        """
        Normalize endpoint URL for deduplication.
        Extracts host + base path (without query params or trailing slashes).
        """
        from urllib.parse import urlparse
        parsed = urlparse(endpoint.lower() if '://' in endpoint else f"https://{endpoint}")
        path = parsed.path.rstrip('/').split('?')[0]
        return f"{parsed.netloc}{path}"

    def _get_endpoint_signature(self, vuln_data: Dict[str, Any]) -> tuple:
        """
        Create a signature for an endpoint to detect duplicates.
        Returns tuple of (host, base_path, vuln_type).
        """
        endpoint = vuln_data.get('endpoint', '')
        vuln_type = vuln_data.get('type', 'unknown')
        normalized = self._normalize_endpoint(endpoint)
        
        # Extract host and base path
        parts = normalized.split('/', 1)
        host = parts[0]
        base_path = '/' + parts[1] if len(parts) > 1 else '/'
        
        # Normalize base path to first 2 levels
        path_parts = base_path.strip('/').split('/')
        if len(path_parts) > 2:
            base_path = '/' + '/'.join(path_parts[:2])
        
        return (host, base_path, vuln_type.lower())

    def should_add_vulnerability(self, vuln_data: Dict[str, Any]) -> bool:
        """
        Check if this vulnerability should be added to the graph.
        Prevents adding duplicate or highly similar endpoints.
        
        Returns:
            True if vulnerability should be added, False if duplicate
        """
        signature = self._get_endpoint_signature(vuln_data)
        vuln_type = vuln_data.get('type', 'unknown').lower()
        
        # Check if exact signature already exists
        if signature in self._added_endpoint_types:
            logger.debug(f"[GRAPH] Skipping duplicate endpoint: {signature}")
            return False
        
        # Check type count limits (max 5 of same type)
        current_count = self._endpoint_type_counts.get(vuln_type, 0)
        if current_count >= 5:
            logger.debug(f"[GRAPH] Max count reached for {vuln_type}: {current_count}")
            return False
        
        # Check similarity with existing endpoints
        for existing_sig in self._added_endpoint_types:
            if self._is_similar_endpoint(signature, existing_sig):
                logger.debug(f"[GRAPH] Skipping similar endpoint: {signature} ~ {existing_sig}")
                return False
        
        return True

    def _is_similar_endpoint(self, sig1: tuple, sig2: tuple) -> bool:
        """
        Check if two endpoint signatures are similar enough to be considered duplicates.
        """
        host1, path1, type1 = sig1
        host2, path2, type2 = sig2
        
        # Different hosts = not similar
        if host1 != host2:
            return False
        
        # Same type and same base path = similar
        if type1 == type2 and path1 == path2:
            return True
        
        # Same type and paths share first segment = similar
        if type1 == type2:
            seg1 = path1.strip('/').split('/')[0] if path1.strip('/') else ''
            seg2 = path2.strip('/').split('/')[0] if path2.strip('/') else ''
            if seg1 == seg2 and seg1:
                return True
        
        return False

    def add_vulnerability_with_dedup(self, vuln_data: Dict[str, Any]) -> Optional[str]:
        """
        Add vulnerability only if it's not a duplicate.
        Returns vuln_id if added, None if skipped.
        """
        if not self.should_add_vulnerability(vuln_data):
            return None
        
        vuln_id = self.add_vulnerability(vuln_data)
        
        # Track this endpoint type
        signature = self._get_endpoint_signature(vuln_data)
        self._added_endpoint_types.add(signature)
        
        vuln_type = vuln_data.get('type', 'unknown').lower()
        self._endpoint_type_counts[vuln_type] = self._endpoint_type_counts.get(vuln_type, 0) + 1
        
        logger.debug(f"[GRAPH] Added vulnerability (type counts: {self._endpoint_type_counts})")
        return vuln_id

    def get_dedup_stats(self) -> Dict[str, Any]:
        """Get statistics about deduplication."""
        return {
            'total_nodes': len(self.graph.nodes),
            'endpoint_types_tracked': len(self._added_endpoint_types),
            'type_counts': dict(self._endpoint_type_counts),
            'chains_found': len(self.exploit_chains),
        }

    def reset_dedup_state(self):
        """Reset deduplication state for new scan session."""
        self._added_endpoint_types.clear()
        self._endpoint_type_counts.clear()
        logger.info("[GRAPH] Reset deduplication state")
