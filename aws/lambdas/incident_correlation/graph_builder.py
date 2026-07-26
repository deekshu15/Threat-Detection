"""
Incident Graph Builder

Builds an entity relationship graph from
validated security events and correlated
event pairs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

from .constants import (
    EDGE_COMMUNICATES,
    EDGE_LOGON,
    EDGE_NETWORK,
    EDGE_PROCESS,
    EDGE_FILE,
    ENTITY_SOURCE_IP,
    ENTITY_DESTINATION_IP,
    ENTITY_HOST,
    ENTITY_USER,
)
from .validator import ValidatedIncidentEvent
from .correlation_engine import CorrelationResult


# ==========================================================
# Graph Models
# ==========================================================

@dataclass
class GraphNode:
    """
    Entity in the attack graph.
    """

    id: str

    entity_type: str

    attributes: Dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    """
    Relationship between entities.
    """

    source: str

    target: str

    relationship: str

    weight: float = 1.0

    attributes: Dict = field(default_factory=dict)


@dataclass
class IncidentGraph:
    """
    Complete graph representation.
    """

    nodes: Dict[str, GraphNode]

    edges: List[GraphEdge]


# ==========================================================
# Graph Builder
# ==========================================================

class GraphBuilder:

    def __init__(self):

        self.nodes: Dict[str, GraphNode] = {}

        self.edges: List[GraphEdge] = []

        self.edge_keys: Set[str] = set()

    # ------------------------------------------------------

    def build_graph(
        self,
        events: List[ValidatedIncidentEvent],
        correlations: List[CorrelationResult],
    ) -> IncidentGraph:

        self.nodes.clear()

        self.edges.clear()

        self.edge_keys.clear()

        for event in events:

            self._add_event_entities(event)

            self._add_event_relationships(event)

        self._add_correlation_edges(correlations)

        return IncidentGraph(

            nodes=self.nodes,

            edges=self.edges,

        )

    # ------------------------------------------------------

    def _add_event_entities(
        self,
        event: ValidatedIncidentEvent,
    ) -> None:

        self._add_node(
            event.src_ip,
            ENTITY_SOURCE_IP,
        )

        self._add_node(
            event.dest_ip,
            ENTITY_DESTINATION_IP,
        )

        self._add_node(
            event.host,
            ENTITY_HOST,
        )

        self._add_node(
            event.user,
            ENTITY_USER,
        )

    # ------------------------------------------------------

    def _add_event_relationships(
        self,
        event: ValidatedIncidentEvent,
    ) -> None:

        self._add_edge(

            event.src_ip,

            event.dest_ip,

            EDGE_NETWORK,

            attributes={

                "protocol": event.protocol,

                "src_port": event.src_port,

                "dest_port": event.dest_port,

            },

        )

        self._add_edge(

            event.user,

            event.host,

            EDGE_LOGON,

        )

        self._add_edge(

            event.host,

            event.src_ip,

            EDGE_COMMUNICATES,

        )

    # ------------------------------------------------------

    def _add_correlation_edges(

        self,

        correlations: List[CorrelationResult],

    ) -> None:

        for correlation in correlations:

            if correlation.score < 60:

                continue

            self._add_edge(

                correlation.event_a,

                correlation.event_b,

                "correlated",

                weight=correlation.score,

            )

    # ------------------------------------------------------

    def _add_node(

        self,

        node_id: str,

        entity_type: str,

        attributes: Dict | None = None,

    ) -> None:

        if not node_id:

            return

        if node_id in self.nodes:

            return

        self.nodes[node_id] = GraphNode(

            id=node_id,

            entity_type=entity_type,

            attributes=attributes or {},

        )

    # ------------------------------------------------------

    def _add_edge(

        self,

        source: str,

        target: str,

        relationship: str,

        weight: float = 1.0,

        attributes: Dict | None = None,

    ) -> None:

        if not source or not target:

            return

        key = f"{source}:{target}:{relationship}"

        if key in self.edge_keys:

            return

        self.edge_keys.add(key)

        self.edges.append(

            GraphEdge(

                source=source,

                target=target,

                relationship=relationship,

                weight=weight,

                attributes=attributes or {},

            )

        )

    # ------------------------------------------------------

    def statistics(self) -> Dict:

        return {

            "nodes": len(self.nodes),

            "edges": len(self.edges),

            "entity_types": len(

                {

                    node.entity_type

                    for node in self.nodes.values()

                }

            ),

        }


# ==========================================================
# Public Helper
# ==========================================================

def build_graph(

    events: List[ValidatedIncidentEvent],

    correlations: List[CorrelationResult],

) -> IncidentGraph:

    """
    Build an incident graph from validated events.
    """

    builder = GraphBuilder()

    return builder.build_graph(

        events,

        correlations,

    )