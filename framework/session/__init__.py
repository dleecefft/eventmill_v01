"""
Event Mill Session Management

Tracks the current investigation state including active pillar,
loaded artifacts, tool execution history, and conversation context.
Session state is persisted to local SQLite.
"""

from .models import (
    Artifact,
    ArtifactType,
    Pillar,
    Session,
    ToolExecution,
    ToolExecutionStatus,
)
from .database import SessionDatabase
from .manager import SessionManager

__all__ = [
    "Artifact",
    "ArtifactType",
    "Pillar",
    "Session",
    "SessionDatabase",
    "SessionManager",
    "ToolExecution",
    "ToolExecutionStatus",
]
