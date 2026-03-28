"""
Event Mill Artifact Registry

Manages artifact registration, lookup, and lifecycle.
Artifacts are immutable after registration.
"""

from __future__ import annotations

import logging
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from ..session.models import Artifact, ArtifactType
from ..plugins.protocol import ArtifactRef

logger = logging.getLogger("eventmill.framework.artifacts")


class ArtifactRegistry:
    """Registry for managing investigation artifacts.
    
    Artifacts are immutable after registration. The registry provides
    lookup by ID, type filtering, and file path resolution.
    """
    
    def __init__(
        self,
        artifacts_path: Path,
        session_id: str,
    ):
        """Initialize artifact registry.
        
        Args:
            artifacts_path: Base path for artifact storage.
            session_id: Current session ID.
        """
        self.artifacts_path = artifacts_path
        self.session_id = session_id
        self._artifacts: dict[str, Artifact] = {}
        
        # Ensure session artifact directory exists
        self.session_path = artifacts_path / session_id
        self.session_path.mkdir(parents=True, exist_ok=True)
    
    def register(
        self,
        artifact_type: str,
        source_path: str | Path,
        source_tool: str | None = None,
        metadata: dict[str, Any] | None = None,
        copy_file: bool = True,
    ) -> ArtifactRef:
        """Register a new artifact.
        
        Args:
            artifact_type: Type of artifact (from ArtifactType).
            source_path: Path to the source file.
            source_tool: Tool that produced this artifact (None for user-loaded).
            metadata: Optional metadata dictionary.
            copy_file: If True, copy file to artifact storage. If False, use path as-is.
        
        Returns:
            ArtifactRef for the registered artifact.
        
        Raises:
            ValueError: If artifact type is invalid.
            FileNotFoundError: If source file doesn't exist.
        """
        # Validate artifact type
        if not ArtifactType.is_valid(artifact_type):
            raise ValueError(f"Invalid artifact type: {artifact_type}")
        
        source_path = Path(source_path)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {source_path}")
        
        # Generate artifact ID
        artifact_id = f"art_{uuid.uuid4().hex[:8]}"
        
        # Determine storage path
        if copy_file:
            # Copy to artifact storage
            ext = source_path.suffix
            dest_path = self.session_path / f"{artifact_id}{ext}"
            shutil.copy2(source_path, dest_path)
            file_path = str(dest_path)
            logger.debug("Copied artifact to: %s", dest_path)
        else:
            file_path = str(source_path)
        
        # Create artifact record
        artifact = Artifact(
            artifact_id=artifact_id,
            session_id=self.session_id,
            artifact_type=artifact_type,
            file_path=file_path,
            source_tool=source_tool,
            created_at=datetime.now(),
            metadata=metadata or {},
        )
        
        # Store in registry
        self._artifacts[artifact_id] = artifact
        
        logger.info(
            "Registered artifact %s (type=%s, source=%s)",
            artifact_id,
            artifact_type,
            source_tool or "user",
        )
        
        return self._to_ref(artifact)
    
    def get(self, artifact_id: str) -> ArtifactRef | None:
        """Get an artifact reference by ID.
        
        Args:
            artifact_id: The artifact ID.
        
        Returns:
            ArtifactRef or None if not found.
        """
        artifact = self._artifacts.get(artifact_id)
        if artifact:
            return self._to_ref(artifact)
        return None
    
    def get_path(self, artifact_id: str) -> Path | None:
        """Get the file path for an artifact.
        
        Args:
            artifact_id: The artifact ID.
        
        Returns:
            Path to the artifact file, or None if not found.
        """
        artifact = self._artifacts.get(artifact_id)
        if artifact:
            return Path(artifact.file_path)
        return None
    
    def list_all(self) -> list[ArtifactRef]:
        """List all registered artifacts."""
        return [self._to_ref(a) for a in self._artifacts.values()]
    
    def list_by_type(self, artifact_type: str) -> list[ArtifactRef]:
        """List artifacts of a specific type.
        
        Args:
            artifact_type: The artifact type to filter by.
        
        Returns:
            List of matching ArtifactRefs.
        """
        return [
            self._to_ref(a)
            for a in self._artifacts.values()
            if a.artifact_type == artifact_type
        ]
    
    def list_by_tool(self, tool_name: str) -> list[ArtifactRef]:
        """List artifacts produced by a specific tool.
        
        Args:
            tool_name: The tool name to filter by.
        
        Returns:
            List of matching ArtifactRefs.
        """
        return [
            self._to_ref(a)
            for a in self._artifacts.values()
            if a.source_tool == tool_name
        ]
    
    def load_from_database(self, artifacts: list[Artifact]) -> None:
        """Load artifacts from database records.
        
        Used when restoring a session.
        
        Args:
            artifacts: List of Artifact records from database.
        """
        for artifact in artifacts:
            self._artifacts[artifact.artifact_id] = artifact
        logger.info("Loaded %d artifacts from database", len(artifacts))
    
    def _to_ref(self, artifact: Artifact) -> ArtifactRef:
        """Convert Artifact to ArtifactRef."""
        return ArtifactRef(
            artifact_id=artifact.artifact_id,
            artifact_type=artifact.artifact_type,
            file_path=artifact.file_path,
            source_tool=artifact.source_tool,
            metadata=artifact.metadata,
        )


def create_artifact_registration_callback(
    registry: ArtifactRegistry,
) -> callable:
    """Create a callback function for plugin artifact registration.
    
    This is passed to ExecutionContext.register_artifact.
    
    Args:
        registry: The artifact registry to use.
    
    Returns:
        Callback function matching the register_artifact signature.
    """
    def register_artifact(
        artifact_type: str,
        file_path: str,
        source_tool: str,
        metadata: dict[str, Any],
    ) -> ArtifactRef:
        return registry.register(
            artifact_type=artifact_type,
            source_path=file_path,
            source_tool=source_tool,
            metadata=metadata,
            copy_file=False,  # Plugin already wrote to workspace
        )
    
    return register_artifact
