"""
Event Mill CLI Shell

Metasploit-style interactive command shell for investigations.
This is the primary user interface for Event Mill.
"""

from __future__ import annotations

import cmd
import os
import sys
from pathlib import Path
from typing import Any

from ..logging.structured import get_logger, setup_logging
from ..session.manager import SessionManager
from ..session.models import Pillar, ToolExecutionStatus
from ..plugins.loader import PluginLoader
from ..routing.router import Router, RouterConfig
from ..artifacts.registry import ArtifactRegistry, create_artifact_registration_callback
from ..llm.client import MCPLLMClient, ContextBuilder
from ..plugins.protocol import ExecutionContext, ReferenceDataView

logger = get_logger("cli")


class EventMillShell(cmd.Cmd):
    """Interactive Event Mill investigation shell.
    
    Provides a Metasploit-style command interface for managing
    sessions, loading artifacts, selecting pillars, and running tools.
    """
    
    intro = (
        "\n"
        "  ╔═══════════════════════════════════════════════╗\n"
        "  ║           Event Mill v0.2.0                   ║\n"
        "  ║   Event Record Analysis Platform              ║\n"
        "  ║   Type 'help' for available commands          ║\n"
        "  ╚═══════════════════════════════════════════════╝\n"
    )
    
    def __init__(
        self,
        workspace_path: str | Path | None = None,
        plugins_path: str | Path | None = None,
    ):
        """Initialize Event Mill shell.
        
        Args:
            workspace_path: Path to workspace directory.
            plugins_path: Path to plugins directory.
        """
        super().__init__()
        
        # Determine paths
        self.project_root = Path(__file__).resolve().parent.parent.parent
        self.workspace_path = Path(
            workspace_path or os.environ.get(
                "EVENTMILL_WORKSPACE",
                self.project_root / "workspace",
            )
        )
        self.plugins_path = Path(
            plugins_path or self.project_root / "plugins"
        )
        
        # Initialize components
        self.session_manager = SessionManager(self.workspace_path)
        self.plugin_loader = PluginLoader(self.plugins_path)
        self.llm_client: MCPLLMClient | None = None
        self.router: Router | None = None
        self.artifact_registry: ArtifactRegistry | None = None
        self.context_builder = ContextBuilder()
        
        # Discover plugins
        discovered = self.plugin_loader.discover_all()
        logger.info("Discovered %d plugins", len(discovered))
        
        # Load routing config
        routing_config_dir = (
            self.project_root / "framework" / "routing" / "config"
        )
        if routing_config_dir.exists():
            try:
                config = RouterConfig.load_from_directory(routing_config_dir)
                self.router = Router(self.plugin_loader, config)
                logger.info("Router initialized")
            except Exception as e:
                logger.warning("Failed to initialize router: %s", e)
        
        self._update_prompt()
    
    def _update_prompt(self) -> None:
        """Update the command prompt based on current state."""
        session = self.session_manager.get_current_session()
        if session:
            pillar = session.active_pillar or "no-pillar"
            self.prompt = f"eventmill ({pillar}) > "
        else:
            self.prompt = "eventmill > "
    
    # -------------------------------------------------------------------
    # Session Commands
    # -------------------------------------------------------------------
    
    def do_new(self, arg: str) -> None:
        """Create a new investigation session.
        
        Usage: new [description]
        """
        description = arg.strip() if arg else ""
        session = self.session_manager.new_session(description=description)
        
        # Initialize artifact registry for session
        self.artifact_registry = ArtifactRegistry(
            artifacts_path=self.workspace_path / "artifacts",
            session_id=session.session_id,
        )
        
        print(f"  Created session: {session.session_id}")
        if description:
            print(f"  Description: {description}")
        self._update_prompt()
    
    def do_load_session(self, arg: str) -> None:
        """Load an existing session.
        
        Usage: load_session <session_id>
        """
        session_id = arg.strip()
        if not session_id:
            print("  Usage: load_session <session_id>")
            return
        
        session = self.session_manager.load_session(session_id)
        if session:
            # Initialize artifact registry
            self.artifact_registry = ArtifactRegistry(
                artifacts_path=self.workspace_path / "artifacts",
                session_id=session.session_id,
            )
            # Load existing artifacts from database
            artifacts = self.session_manager.list_artifacts()
            self.artifact_registry.load_from_database(artifacts)
            
            print(f"  Loaded session: {session.session_id}")
            print(f"  Pillar: {session.active_pillar or 'none'}")
        else:
            print(f"  Session not found: {session_id}")
        self._update_prompt()
    
    def do_sessions(self, arg: str) -> None:
        """List all sessions.
        
        Usage: sessions
        """
        sessions = self.session_manager.list_sessions()
        if not sessions:
            print("  No sessions found.")
            return
        
        current = self.session_manager.get_current_session()
        print(f"  {'':2s} {'Session ID':20s} {'Pillar':20s} {'Updated':20s} Description")
        print(f"  {'':2s} {'─' * 20} {'─' * 20} {'─' * 20} {'─' * 20}")
        
        for s in sessions:
            marker = "▸ " if current and s.session_id == current.session_id else "  "
            pillar = s.active_pillar or "—"
            updated = s.updated_at.strftime("%Y-%m-%d %H:%M")
            desc = s.description[:30] if s.description else "—"
            print(f"  {marker}{s.session_id:20s} {pillar:20s} {updated:20s} {desc}")
    
    def do_delete_session(self, arg: str) -> None:
        """Delete a session.
        
        Usage: delete_session <session_id>
        """
        session_id = arg.strip()
        if not session_id:
            print("  Usage: delete_session <session_id>")
            return
        
        self.session_manager.delete_session(session_id)
        print(f"  Deleted session: {session_id}")
        self._update_prompt()
    
    # -------------------------------------------------------------------
    # Pillar Commands
    # -------------------------------------------------------------------
    
    def do_pillar(self, arg: str) -> None:
        """Set or show the active investigation pillar.
        
        Usage: pillar [pillar_name]
        
        Available pillars: log_analysis, network_forensics,
        threat_modeling, cloud_investigation, risk_assessment
        """
        if not self.session_manager.get_current_session():
            print("  No active session. Use 'new' to create one.")
            return
        
        pillar = arg.strip()
        if not pillar:
            # Show current pillar
            session = self.session_manager.get_current_session()
            if session.active_pillar:
                print(f"  Active pillar: {session.active_pillar}")
                
                # Show tools for this pillar
                tools = self.plugin_loader.get_by_pillar(session.active_pillar)
                if tools:
                    print(f"  Available tools ({len(tools)}):")
                    for tool in tools:
                        print(
                            f"    - {tool.manifest.display_name} "
                            f"({tool.tool_name})"
                        )
            else:
                print("  No pillar selected. Available pillars:")
                for p in sorted(Pillar.ALL):
                    count = len(self.plugin_loader.get_by_pillar(p))
                    print(f"    - {p} ({count} tools)")
            return
        
        if not Pillar.is_valid(pillar):
            print(f"  Invalid pillar: {pillar}")
            print(f"  Valid pillars: {', '.join(sorted(Pillar.ALL))}")
            return
        
        self.session_manager.set_pillar(pillar)
        tools = self.plugin_loader.get_by_pillar(pillar)
        print(f"  Pillar set to: {pillar} ({len(tools)} tools available)")
        self._update_prompt()
    
    # -------------------------------------------------------------------
    # Artifact Commands
    # -------------------------------------------------------------------
    
    def do_load(self, arg: str) -> None:
        """Load an artifact file into the current session.
        
        Usage: load <file_path> [artifact_type]
        
        Supported types: pcap, json_events, log_stream, risk_model,
        cloud_audit_log, pdf_report, html_report, image, text
        """
        if not self.session_manager.get_current_session():
            print("  No active session. Use 'new' to create one.")
            return
        
        parts = arg.strip().split(maxsplit=1)
        if not parts:
            print("  Usage: load <file_path> [artifact_type]")
            return
        
        file_path = Path(parts[0])
        if not file_path.exists():
            print(f"  File not found: {file_path}")
            return
        
        # Infer or use specified artifact type
        artifact_type = parts[1] if len(parts) > 1 else self._infer_artifact_type(file_path)
        
        artifact = self.session_manager.register_artifact(
            artifact_type=artifact_type,
            file_path=str(file_path.resolve()),
            metadata={"original_filename": file_path.name},
        )
        
        if self.artifact_registry:
            self.artifact_registry.register(
                artifact_type=artifact_type,
                source_path=file_path,
                metadata={"original_filename": file_path.name},
                copy_file=False,
            )
        
        print(f"  Loaded artifact: {artifact.artifact_id}")
        print(f"  Type: {artifact_type}")
        print(f"  File: {file_path.name}")
    
    def do_artifacts(self, arg: str) -> None:
        """List loaded artifacts in the current session.
        
        Usage: artifacts
        """
        if not self.session_manager.get_current_session():
            print("  No active session.")
            return
        
        artifacts = self.session_manager.list_artifacts()
        if not artifacts:
            print("  No artifacts loaded. Use 'load <file_path>' to add one.")
            return
        
        print(f"  {'ID':12s} {'Type':16s} {'Source':16s} File")
        print(f"  {'─' * 12} {'─' * 16} {'─' * 16} {'─' * 30}")
        
        for a in artifacts:
            source = a.source_tool or "user"
            filename = Path(a.file_path).name
            print(f"  {a.artifact_id:12s} {a.artifact_type:16s} {source:16s} {filename}")
    
    # -------------------------------------------------------------------
    # Tool Commands
    # -------------------------------------------------------------------
    
    def do_tools(self, arg: str) -> None:
        """List available tools.
        
        Usage: tools [pillar]
        """
        pillar = arg.strip() if arg else None
        
        if pillar:
            plugins = self.plugin_loader.get_by_pillar(pillar)
        else:
            plugins = self.plugin_loader.list_all()
        
        if not plugins:
            print("  No tools available.")
            return
        
        print(f"  {'Tool':30s} {'Pillar':20s} {'Stability':12s} Description")
        print(f"  {'─' * 30} {'─' * 20} {'─' * 12} {'─' * 30}")
        
        for p in plugins:
            m = p.manifest
            desc = m.description_short[:40] if m.description_short else "—"
            print(f"  {m.display_name:30s} {m.pillar:20s} {m.stability:12s} {desc}")
    
    def do_run(self, arg: str) -> None:
        """Run a tool on the current session.
        
        Usage: run <tool_name> [json_payload]
        """
        if not self.session_manager.get_current_session():
            print("  No active session. Use 'new' to create one.")
            return
        
        parts = arg.strip().split(maxsplit=1)
        if not parts:
            print("  Usage: run <tool_name> [json_payload]")
            return
        
        tool_name = parts[0]
        plugin = self.plugin_loader.get(tool_name)
        
        if not plugin:
            print(f"  Tool not found: {tool_name}")
            return
        
        # Parse payload
        import json
        payload = {}
        if len(parts) > 1:
            try:
                payload = json.loads(parts[1])
            except json.JSONDecodeError as e:
                print(f"  Invalid JSON payload: {e}")
                return
        
        # Get plugin instance
        instance = plugin.get_instance()
        
        # Validate inputs
        validation = instance.validate_inputs(payload)
        if not validation.ok:
            print(f"  Input validation failed:")
            for error in (validation.errors or []):
                print(f"    - {error}")
            return
        
        # Build execution context
        session = self.session_manager.get_current_session()
        artifact_refs = []
        if self.artifact_registry:
            artifact_refs = self.artifact_registry.list_all()
        
        context = ExecutionContext(
            session_id=session.session_id,
            selected_pillar=session.active_pillar or "",
            artifacts=artifact_refs,
            llm_enabled=self.llm_client is not None and self.llm_client.connected,
            llm_query=self.llm_client,
            register_artifact=(
                create_artifact_registration_callback(self.artifact_registry)
                if self.artifact_registry
                else None
            ),
            reference_data=ReferenceDataView(),
        )
        
        # Track execution
        execution = self.session_manager.start_execution(
            tool_name=tool_name,
        )
        
        print(f"  Running {plugin.manifest.display_name}...")
        
        try:
            result = instance.execute(payload, context)
            
            if result.ok:
                summary = instance.summarize_for_llm(result)
                self.session_manager.complete_execution(
                    execution=execution,
                    status=ToolExecutionStatus.COMPLETED,
                    summary=summary,
                )
                print(f"  ✓ Completed successfully")
                print(f"\n  Summary:\n  {summary}")
            else:
                self.session_manager.complete_execution(
                    execution=execution,
                    status=ToolExecutionStatus.FAILED,
                    summary=result.message or "",
                )
                print(f"  ✗ Failed: {result.error_code}")
                if result.message:
                    print(f"    {result.message}")
                    
        except Exception as e:
            self.session_manager.complete_execution(
                execution=execution,
                status=ToolExecutionStatus.FAILED,
                summary=str(e),
            )
            print(f"  ✗ Error: {e}")
            logger.exception("Tool execution failed: %s", tool_name)
    
    def do_history(self, arg: str) -> None:
        """Show tool execution history for the current session.
        
        Usage: history
        """
        if not self.session_manager.get_current_session():
            print("  No active session.")
            return
        
        executions = self.session_manager.list_executions()
        if not executions:
            print("  No tool executions yet.")
            return
        
        print(f"  {'ID':14s} {'Tool':24s} {'Status':12s} {'Time':20s}")
        print(f"  {'─' * 14} {'─' * 24} {'─' * 12} {'─' * 20}")
        
        for e in executions:
            time_str = e.started_at.strftime("%Y-%m-%d %H:%M:%S")
            print(f"  {e.execution_id:14s} {e.tool_name:24s} {e.status.value:12s} {time_str}")
    
    # -------------------------------------------------------------------
    # Route Command
    # -------------------------------------------------------------------
    
    def do_route(self, arg: str) -> None:
        """Show routing decision for a query.
        
        Usage: route <query>
        """
        if not self.router:
            print("  Router not initialized.")
            return
        
        query = arg.strip()
        if not query:
            print("  Usage: route <query>")
            return
        
        session = self.session_manager.get_current_session()
        artifact_types = []
        if self.artifact_registry:
            artifact_types = list(set(
                a.artifact_type for a in self.artifact_registry.list_all()
            ))
        
        result = self.router.route(
            user_input=query,
            artifact_types=artifact_types,
            active_pillar=session.active_pillar if session else None,
        )
        
        print(f"\n  {result.explanation}")
        
        if result.chain_recommendations:
            print(f"\n  Chain recommendations: {', '.join(result.chain_recommendations)}")
    
    # -------------------------------------------------------------------
    # Utility Commands
    # -------------------------------------------------------------------
    
    def do_status(self, arg: str) -> None:
        """Show current investigation status.
        
        Usage: status
        """
        session = self.session_manager.get_current_session()
        if not session:
            print("  No active session. Use 'new' to create one.")
            return
        
        artifacts = self.session_manager.list_artifacts()
        executions = self.session_manager.list_executions()
        completed = sum(
            1 for e in executions
            if e.status == ToolExecutionStatus.COMPLETED
        )
        
        print(f"  Session:    {session.session_id}")
        print(f"  Pillar:     {session.active_pillar or '—'}")
        print(f"  Artifacts:  {len(artifacts)}")
        print(f"  Executions: {len(executions)} ({completed} completed)")
        print(f"  Created:    {session.created_at.strftime('%Y-%m-%d %H:%M')}")
        print(f"  Updated:    {session.updated_at.strftime('%Y-%m-%d %H:%M')}")
        
        if session.description:
            print(f"  Description: {session.description}")
        
        # Show recent summaries
        summaries = self.session_manager.get_recent_summaries(limit=3)
        if summaries:
            print(f"\n  Recent findings:")
            for s in summaries:
                # Truncate long summaries for display
                display = s[:100] + "..." if len(s) > 100 else s
                print(f"    {display}")
    
    def do_connect(self, arg: str) -> None:
        """Connect to LLM via MCP.
        
        Usage: connect [model_id]
        """
        model_id = arg.strip() or os.environ.get(
            "EVENTMILL_MODEL_ID", "gemini-2.5-flash"
        )
        transport = os.environ.get("EVENTMILL_MCP_TRANSPORT", "stdio")
        
        self.llm_client = MCPLLMClient(
            model_id=model_id,
            transport=transport,
        )
        
        print(f"  LLM client configured: {model_id} ({transport})")
        print("  Note: MCP transport integration pending implementation.")
    
    def do_exit(self, arg: str) -> bool:
        """Exit Event Mill.
        
        Usage: exit
        """
        print("  Goodbye.")
        return True
    
    def do_quit(self, arg: str) -> bool:
        """Exit Event Mill.
        
        Usage: quit
        """
        return self.do_exit(arg)
    
    def do_EOF(self, arg: str) -> bool:
        """Handle Ctrl+D."""
        print()
        return self.do_exit(arg)
    
    def emptyline(self) -> None:
        """Do nothing on empty input."""
        pass
    
    def default(self, line: str) -> None:
        """Handle unknown commands."""
        print(f"  Unknown command: {line.split()[0]}")
        print("  Type 'help' for available commands.")
    
    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------
    
    def _infer_artifact_type(self, file_path: Path) -> str:
        """Infer artifact type from file extension."""
        ext = file_path.suffix.lower()
        
        type_map = {
            ".pcap": "pcap",
            ".pcapng": "pcap",
            ".json": "json_events",
            ".log": "log_stream",
            ".txt": "text",
            ".csv": "text",
            ".pdf": "pdf_report",
            ".html": "html_report",
            ".htm": "html_report",
            ".png": "image",
            ".jpg": "image",
            ".jpeg": "image",
            ".gif": "image",
            ".bmp": "image",
        }
        
        return type_map.get(ext, "text")


def main() -> None:
    """Entry point for the Event Mill CLI."""
    # Setup logging
    log_level = os.environ.get("EVENTMILL_LOG_LEVEL", "INFO")
    workspace = Path(
        os.environ.get("EVENTMILL_WORKSPACE", "./workspace")
    )
    log_file = workspace / "logs" / "eventmill.log"
    
    setup_logging(
        log_level=log_level,
        log_file=log_file,
        console=True,
    )
    
    try:
        shell = EventMillShell()
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\n  Interrupted. Goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()
