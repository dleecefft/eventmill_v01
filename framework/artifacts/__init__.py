"""
Event Mill Artifact Registry

Tracks all investigation artifacts in the current session.
Artifacts are immutable after registration.
"""

from .registry import ArtifactRegistry, create_artifact_registration_callback

__all__ = [
    "ArtifactRegistry",
    "create_artifact_registration_callback",
]
