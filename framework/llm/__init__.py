"""
Event Mill LLM Integration

MCP client wrapper and context management for LLM interactions.
Plugins access the LLM exclusively through this interface.
"""

from .client import MCPLLMClient, ContextBuilder

__all__ = [
    "ContextBuilder",
    "MCPLLMClient",
]
