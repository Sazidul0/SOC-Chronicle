"""Investigation graph engine backed by NetworkX."""

from __future__ import annotations

from typing import Any

import networkx as nx

from soc_chronicle.models.event import NormalizedEvent, OCSFClass
from soc_chronicle.models.graph import EdgeType, GraphEdge, GraphNode, InvestigationGraph, NodeType


class InvestigationGraphEngine:
    """Build and analyze attack graphs from normalized events."""

    def build(self, events: list[NormalizedEvent]) -> InvestigationGraph:
        graph = nx.DiGraph()
        for event in events:
            self._add_event(graph, event)
        return self._to_model(graph)

    def shortest_path(self, graph: InvestigationGraph, source: str, target: str) -> list[str] | None:
        nx_graph = self._from_model(graph)
        try:
            return nx.shortest_path(nx_graph, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def connected_components(self, graph: InvestigationGraph) -> list[list[str]]:
        nx_graph = self._from_model(graph).to_undirected()
        return [list(c) for c in nx.connected_components(nx_graph)]

    def blast_radius(self, graph: InvestigationGraph, origin_node: str) -> int:
        nx_graph = self._from_model(graph).to_undirected()
        if origin_node not in nx_graph:
            return 0
        reachable = nx.node_connected_component(nx_graph, origin_node)
        return max(len(reachable) - 1, 0)

    def detect_lateral_movement(self, graph: InvestigationGraph) -> list[GraphEdge]:
        lateral: list[GraphEdge] = []
        host_nodes = {n.id: n for n in graph.nodes if n.type == NodeType.DEVICE}
        for edge in graph.edges:
            if edge.type == EdgeType.CONNECTED:
                src = host_nodes.get(edge.source)
                tgt = host_nodes.get(edge.target)
                if src and tgt and src.id != tgt.id:
                    lateral.append(edge)
        return lateral

    def _add_event(self, graph: nx.DiGraph, event: NormalizedEvent) -> None:
        host_id = self._ensure_node(graph, NodeType.DEVICE, event.host or "unknown-host")
        if event.user:
            user_id = self._ensure_node(graph, NodeType.USER, event.user)
            graph.add_edge(user_id, host_id, type=EdgeType.AUTHENTICATED.value, ts=event.timestamp)
        if event.process_name:
            proc_id = self._ensure_node(
                graph, NodeType.PROCESS, event.process_name, {"pid": event.process_pid}
            )
            graph.add_edge(proc_id, host_id, type=EdgeType.EXECUTED.value, ts=event.timestamp)
            if event.parent_process_name:
                parent_id = self._ensure_node(graph, NodeType.PROCESS, event.parent_process_name)
                graph.add_edge(parent_id, proc_id, type=EdgeType.SPAWNED.value, ts=event.timestamp)
        if event.file_path:
            file_id = self._ensure_node(graph, NodeType.FILE, event.file_path, {"hash": event.file_hash})
            proc = event.process_name or "unknown-process"
            proc_id = self._ensure_node(graph, NodeType.PROCESS, proc)
            edge_type = EdgeType.CREATED if event.class_uid == OCSFClass.FILE_ACTIVITY else EdgeType.MODIFIED
            graph.add_edge(proc_id, file_id, type=edge_type.value, ts=event.timestamp)
        if event.registry_key:
            reg_id = self._ensure_node(graph, NodeType.REGISTRY, event.registry_key)
            proc = event.process_name or "unknown-process"
            proc_id = self._ensure_node(graph, NodeType.PROCESS, proc)
            graph.add_edge(proc_id, reg_id, type=EdgeType.MODIFIED.value, ts=event.timestamp)
        if event.dst_ip or event.domain:
            target = event.domain or event.dst_ip or "unknown"
            node_type = NodeType.DOMAIN if event.domain else NodeType.IP
            remote_id = self._ensure_node(graph, node_type, target)
            proc = event.process_name or event.host or "unknown"
            src_id = self._ensure_node(
                graph, NodeType.PROCESS if event.process_name else NodeType.DEVICE, proc
            )
            graph.add_edge(src_id, remote_id, type=EdgeType.CONNECTED.value, ts=event.timestamp)

    @staticmethod
    def _ensure_node(
        graph: nx.DiGraph, node_type: NodeType, label: str, props: dict[str, Any] | None = None
    ) -> str:
        node_id = f"{node_type.value}:{label.lower()}"
        if node_id not in graph:
            graph.add_node(node_id, type=node_type.value, label=label, **(props or {}))
        return node_id

    @staticmethod
    def _to_model(graph: nx.DiGraph) -> InvestigationGraph:
        nodes = [
            GraphNode(
                id=node_id,
                type=NodeType(data.get("type", NodeType.DEVICE.value)),
                label=str(data.get("label", node_id)),
                properties={k: v for k, v in data.items() if k not in {"type", "label"}},
            )
            for node_id, data in graph.nodes(data=True)
        ]
        edges = [
            GraphEdge(
                source=u,
                target=v,
                type=EdgeType(data.get("type", EdgeType.CONNECTED.value)),
                timestamp=str(data.get("ts")) if data.get("ts") else None,
            )
            for u, v, data in graph.edges(data=True)
        ]
        return InvestigationGraph(nodes=nodes, edges=edges)

    @staticmethod
    def _from_model(model: InvestigationGraph) -> nx.DiGraph:
        graph = nx.DiGraph()
        for node in model.nodes:
            graph.add_node(node.id, type=node.type.value, label=node.label, **node.properties)
        for edge in model.edges:
            graph.add_edge(edge.source, edge.target, type=edge.type.value, ts=edge.timestamp)
        return graph
