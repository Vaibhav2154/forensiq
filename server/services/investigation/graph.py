"""LangGraph StateGraph assembly for the ForensIQ multi-agent investigation workflow."""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from services.investigation.agents import (
    make_attack_path_node,
    make_correlation_timeline_node,
    make_event_analyst_node,
    make_knowledge_enricher_node,
    make_orchestrator_plan_node,
    make_orchestrator_review_node,
    make_orchestrator_synthesize_node,
    make_recommendation_drafter_node,
    make_sequence_analyst_node,
    route_after_review,
)
from services.investigation.llm_factory import GeminiAgentFactory
from services.investigation.state import InvestigationState
from services.knowledge import KnowledgeService


def build_investigation_graph(
    llm_factory: GeminiAgentFactory,
    knowledge_service: KnowledgeService | None = None,
    max_refinement_rounds: int | None = None,
):
    """Compile the ForensIQ multi-agent LangGraph StateGraph.

    Graph topology:
        START
          -> orchestrator_plan
          -> [event_analyst, knowledge_enricher, sequence_analyst]   (parallel fan-out)
          -> correlation_timeline                                    (fan-in join)
          -> attack_path_analyst
          -> orchestrator_review
             |-- "refine_knowledge"      -> knowledge_refiner -> attack_path_analyst -> orchestrator_review
             |-- "refine_attack_path"    -> attack_path_analyst -> orchestrator_review
             |-- "draft_recommendations" -> recommendation_drafter -> orchestrator_synthesize -> END
             |-- "synthesize_only"       -> orchestrator_synthesize -> END
    """
    rounds = (
        llm_factory.settings.max_refinement_rounds
        if max_refinement_rounds is None
        else max_refinement_rounds
    )

    builder = StateGraph(InvestigationState)

    # Register nodes
    builder.add_node("orchestrator_plan", make_orchestrator_plan_node(rounds))
    builder.add_node("event_analyst", make_event_analyst_node(llm_factory))
    builder.add_node(
        "knowledge_enricher",
        make_knowledge_enricher_node(
            llm_factory=llm_factory,
            knowledge_service=knowledge_service,
            node_name="knowledge_enricher",
        ),
    )
    builder.add_node("sequence_analyst", make_sequence_analyst_node(llm_factory))
    builder.add_node("correlation_timeline", make_correlation_timeline_node(llm_factory))
    builder.add_node("attack_path_analyst", make_attack_path_node(llm_factory))
    builder.add_node("orchestrator_review", make_orchestrator_review_node(llm_factory))
    builder.add_node(
        "knowledge_refiner",
        make_knowledge_enricher_node(
            llm_factory=llm_factory,
            knowledge_service=knowledge_service,
            node_name="knowledge_refiner",
        ),
    )
    builder.add_node(
        "recommendation_drafter", make_recommendation_drafter_node(llm_factory)
    )
    builder.add_node(
        "orchestrator_synthesize", make_orchestrator_synthesize_node(llm_factory)
    )

    # Phase 0 -> Phase 1 parallel fan-out
    builder.add_edge(START, "orchestrator_plan")
    builder.add_edge("orchestrator_plan", "event_analyst")
    builder.add_edge("orchestrator_plan", "knowledge_enricher")
    builder.add_edge("orchestrator_plan", "sequence_analyst")

    # Phase 1 fan-in join -> Phase 2
    builder.add_edge(
        ["event_analyst", "knowledge_enricher", "sequence_analyst"],
        "correlation_timeline",
    )
    builder.add_edge("correlation_timeline", "attack_path_analyst")
    builder.add_edge("attack_path_analyst", "orchestrator_review")

    # Phase 3 conditional review routing (bounded refinement or synthesis)
    builder.add_conditional_edges(
        "orchestrator_review",
        route_after_review,
        {
            "refine_knowledge": "knowledge_refiner",
            "refine_attack_path": "attack_path_analyst",
            "draft_recommendations": "recommendation_drafter",
            "synthesize_only": "orchestrator_synthesize",
        },
    )
    builder.add_edge("knowledge_refiner", "attack_path_analyst")
    builder.add_edge("recommendation_drafter", "orchestrator_synthesize")
    builder.add_edge("orchestrator_synthesize", END)

    return builder.compile()
