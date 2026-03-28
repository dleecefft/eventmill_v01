"""
Tests for session management.
"""

import pytest
from datetime import datetime
from pathlib import Path

from framework.session import (
    Session,
    SessionManager,
    Artifact,
    ArtifactType,
    ToolExecution,
    ToolExecutionStatus,
)


class TestSessionManager:
    """Tests for SessionManager."""
    
    def test_new_session(self, temp_workspace: Path):
        """Test creating a new session."""
        manager = SessionManager(temp_workspace)
        session = manager.new_session(description="Test investigation")
        
        assert session.session_id.startswith("sess_")
        assert session.description == "Test investigation"
        assert session.active_pillar is None
        assert manager.get_current_session() == session
    
    def test_load_session(self, temp_workspace: Path):
        """Test loading an existing session."""
        manager = SessionManager(temp_workspace)
        session = manager.new_session()
        session_id = session.session_id
        
        # Create new manager and load session
        manager2 = SessionManager(temp_workspace)
        loaded = manager2.load_session(session_id)
        
        assert loaded is not None
        assert loaded.session_id == session_id
    
    def test_set_pillar(self, temp_workspace: Path):
        """Test setting the active pillar."""
        manager = SessionManager(temp_workspace)
        manager.new_session()
        
        manager.set_pillar("log_analysis")
        
        session = manager.get_current_session()
        assert session.active_pillar == "log_analysis"
    
    def test_register_artifact(self, temp_workspace: Path, sample_artifact_file: Path):
        """Test registering an artifact."""
        manager = SessionManager(temp_workspace)
        manager.new_session()
        
        artifact = manager.register_artifact(
            artifact_type="text",
            file_path=str(sample_artifact_file),
            metadata={"test": "value"},
        )
        
        assert artifact.artifact_id.startswith("art_")
        assert artifact.artifact_type == "text"
        assert artifact.metadata == {"test": "value"}
    
    def test_list_artifacts(self, temp_workspace: Path, sample_artifact_file: Path):
        """Test listing artifacts."""
        manager = SessionManager(temp_workspace)
        manager.new_session()
        
        manager.register_artifact(artifact_type="text", file_path=str(sample_artifact_file))
        manager.register_artifact(artifact_type="text", file_path=str(sample_artifact_file))
        
        artifacts = manager.list_artifacts()
        assert len(artifacts) == 2
    
    def test_list_artifacts_by_type(self, temp_workspace: Path, sample_artifact_file: Path):
        """Test filtering artifacts by type."""
        manager = SessionManager(temp_workspace)
        manager.new_session()
        
        manager.register_artifact(artifact_type="text", file_path=str(sample_artifact_file))
        manager.register_artifact(artifact_type="json_events", file_path=str(sample_artifact_file))
        
        text_artifacts = manager.list_artifacts(artifact_type="text")
        assert len(text_artifacts) == 1
        assert text_artifacts[0].artifact_type == "text"
    
    def test_execution_tracking(self, temp_workspace: Path):
        """Test tool execution tracking."""
        manager = SessionManager(temp_workspace)
        manager.new_session()
        
        execution = manager.start_execution(tool_name="test_tool")
        assert execution.status == ToolExecutionStatus.RUNNING
        
        manager.complete_execution(
            execution=execution,
            status=ToolExecutionStatus.COMPLETED,
            summary="Test completed successfully",
        )
        
        executions = manager.list_executions()
        assert len(executions) == 1
        assert executions[0].status == ToolExecutionStatus.COMPLETED
    
    def test_recent_summaries(self, temp_workspace: Path):
        """Test getting recent execution summaries."""
        manager = SessionManager(temp_workspace)
        manager.new_session()
        
        for i in range(5):
            execution = manager.start_execution(tool_name=f"tool_{i}")
            manager.complete_execution(
                execution=execution,
                status=ToolExecutionStatus.COMPLETED,
                summary=f"Summary {i}",
            )
        
        summaries = manager.get_recent_summaries(limit=3)
        assert len(summaries) == 3
        # Most recent first
        assert summaries[0] == "Summary 4"
    
    def test_delete_session(self, temp_workspace: Path):
        """Test deleting a session."""
        manager = SessionManager(temp_workspace)
        session = manager.new_session()
        session_id = session.session_id
        
        manager.delete_session(session_id)
        
        assert manager.get_current_session() is None
        assert manager.load_session(session_id) is None


class TestArtifactType:
    """Tests for ArtifactType validation."""
    
    def test_valid_types(self):
        """Test that all expected types are valid."""
        valid_types = [
            "pcap", "json_events", "log_stream", "risk_model",
            "cloud_audit_log", "pdf_report", "html_report", "image", "text", "none"
        ]
        for t in valid_types:
            assert ArtifactType.is_valid(t)
    
    def test_invalid_type(self):
        """Test that invalid types are rejected."""
        assert not ArtifactType.is_valid("invalid_type")
        assert not ArtifactType.is_valid("")
