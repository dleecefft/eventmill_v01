"""
Event Mill Routing Layer

Controls which plugins are visible to the LLM at any point in the
investigation. Prevents context bloat from exposing the entire tool catalog.
"""

from .router import Router, RouterConfig, RoutingResult, RoutingScore

__all__ = [
    "Router",
    "RouterConfig",
    "RoutingResult",
    "RoutingScore",
]
