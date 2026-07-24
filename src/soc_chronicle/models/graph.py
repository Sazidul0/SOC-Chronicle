"""Investigation graph models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class NodeType(StrEnum):
    USER = "user"
    DEVICE = "device"
    PROCESS = "process"
    IP = "ip"
    DOMAIN = "domain"
    FILE = "file"
    REGISTRY = "registry"
    SERVICE = "service"
    SCHEDULED_TASK = "scheduled_task"


class EdgeType(StrEnum):
    EXECUTED = "executed"
    SPAWNED = "spawned"
    CONNECTED = "connected"
    AUTHENTICATED = "authenticated"
    DOWNLOADED = "downloaded"
    MODIFIED = "modified"
    CREATED = "created"
    INJECTED = "injected"


class GraphNode(BaseModel):
    id: str
    type: NodeType
    label: str
    properties: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)


class GraphEdge(BaseModel):
    source: str
    target: str
    type: EdgeType
    timestamp: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class InvestigationGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)

    def node_count(self) -> int:
        return len(self.nodes)

    def edge_count(self) -> int:
        return len(self.edges)
