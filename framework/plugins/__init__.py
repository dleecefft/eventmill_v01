"""
Event Mill Plugin Lifecycle

Discovery, validation, loading, and execution of plugins.
See tool_plugin_spec.md for the normative contract.
"""

from .protocol import (
    ArtifactRef,
    ErrorCodes,
    EventMillToolProtocol,
    ExecutionContext,
    LLMQueryInterface,
    LLMResponse,
    ReferenceDataView,
    TimeoutClass,
    ToolResult,
    ValidationResult,
)
from .loader import LoadedPlugin, PluginLoader, PluginManifest
from .executor import ExecutionResult, PluginExecutor

__all__ = [
    "ArtifactRef",
    "ErrorCodes",
    "EventMillToolProtocol",
    "ExecutionContext",
    "LLMQueryInterface",
    "LLMResponse",
    "ExecutionResult",
    "LoadedPlugin",
    "PluginExecutor",
    "PluginLoader",
    "PluginManifest",
    "ReferenceDataView",
    "TimeoutClass",
    "ToolResult",
    "ValidationResult",
]
