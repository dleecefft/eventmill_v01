"""
Event Mill CLI Shell

Metasploit-style interactive command shell for investigations.
This is the primary user interface for Event Mill.
"""

from __future__ import annotations

import cmd
import json
import os
import random
import shlex
import signal
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from ..logging.structured import get_logger, setup_logging, log_user_activity, log_llm_interaction, set_user_context
from ..session.manager import SessionManager
from ..session.models import Pillar, ToolExecutionStatus
from ..plugins.loader import PluginLoader, LoadedPlugin
from ..routing.router import Router, RouterConfig
from ..artifacts.registry import ArtifactRegistry, create_artifact_registration_callback
from ..llm.client import MCPLLMClient, ContextBuilder, TieredLLMClient
from ..plugins.protocol import ExecutionContext, ReferenceDataView, ArtifactRef, TimeoutClass
from ..cloud.resolver import StorageResolver, StorageResolverConfig, create_local_resolver

logger = get_logger("cli")


# ---------------------------------------------------------------------------
# Metasploit-style random startup banners
# ---------------------------------------------------------------------------

_BANNERS = [
    r"""
     _____ _   _ _____ _   _ _____   __  __ ___ _     _
    | ____| | | | ____| \ | |_   _| |  \/  |_ _| |   | |
    |  _| | | | |  _| |  \| | | |   | |\/| || || |   | |
    | |___| |_| | |___| |\  | | |   | |  | || || |___| |___
    |_____|\___/|_____|_| \_| |_|   |_|  |_|___|_____|_____|
""",
    r"""
    ╔══════════════════════════════════════════════════════╗
    ║  ███████╗██╗   ██╗███████╗███╗   ██╗████████╗       ║
    ║  ██╔════╝██║   ██║██╔════╝████╗  ██║╚══██╔══╝       ║
    ║  █████╗  ██║   ██║█████╗  ██╔██╗ ██║   ██║          ║
    ║  ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║   ██║          ║
    ║  ███████╗ ╚████╔╝ ███████╗██║ ╚████║   ██║          ║
    ║  ╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝   ╚═╝          ║
    ║              M  I  L  L                             ║
    ╚══════════════════════════════════════════════════════╝
""",
    r"""
               _             _
     _____   _| |_     _ __ (_) | |
    / _ \ \ / / __|   | '_ \| | | |
   |  __/\ V /| |_    | | | | | | |
    \___| \_/  \__|   |_| |_|_|_|_|
      event           mill
""",
    r"""
    ┌─────────────────────────────────────────┐
    │  ╺━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╸  │
    │     E V E N T   M I L L   v0.1.0       │
    │   event record analysis platform       │
    │  ╺━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╸  │
    └─────────────────────────────────────────┘
""",
    r"""
        ____                 __     __  ___ _  __  __
       / __/ _  __ ___  ___ / /_   /  |/  /(_)/ / / /
      / _/  | |/ // -_)/ _ / __/  / /|_/ // // / / /
     /___/  |___/ \__//_//_\__/  /_/  /_//_//_/ /_/
""",
    r"""
      .--.      .--.      .--.      .--.
     /    \    /    \    /    \    /    \
    | EVNT |--| MILL |--| v0.1|--| .0  |
     \    /    \    /    \    /    \    /
      `--'      `--'      `--'      `--'
      upstream of the SIEM — analysis before commitment
""",
]

# ANSI color codes — a random one is picked each launch
_COLORS = [
    "\033[1;31m",  # bold red
    "\033[1;32m",  # bold green
    "\033[1;33m",  # bold yellow
    "\033[1;34m",  # bold blue
    "\033[1;35m",  # bold magenta
    "\033[1;36m",  # bold cyan
    "\033[0;91m",  # light red
    "\033[0;92m",  # light green
    "\033[0;93m",  # light yellow
    "\033[0;94m",  # light blue
    "\033[0;95m",  # light magenta
    "\033[0;96m",  # light cyan
]
_RESET = "\033[0m"


def _random_banner() -> str:
    """Return a randomly colored ASCII art banner."""
    art = random.choice(_BANNERS)
    color = random.choice(_COLORS)
    return f"{color}{art}{_RESET}"


class EventMillShell(cmd.Cmd):
    """Interactive Event Mill investigation shell.
    
    Provides a Metasploit-style command interface for managing
    sessions, loading artifacts, selecting pillars, and running tools.
    """
    
    # Intro is set dynamically in preloop() to include startup stats
    intro = ""
    
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
        self.llm_client: MCPLLMClient | TieredLLMClient | None = None
        self.router: Router | None = None
        self.artifact_registry: ArtifactRegistry | None = None
        self.context_builder = ContextBuilder()
        self._conversation_history: list[dict[str, str]] = []
        
        # Initialize storage resolver
        # In Cloud Run (K_SERVICE set), use GCS resolver; otherwise local
        if os.environ.get("K_SERVICE"):
            try:
                from ..cloud.resolver import create_gcs_resolver
                self.storage_resolver: StorageResolver | None = create_gcs_resolver()
            except Exception as e:
                logger.warning("Failed to create GCS resolver: %s", e)
                self.storage_resolver = None
        else:
            storage_base = self.workspace_path / "storage"
            self.storage_resolver = create_local_resolver(base_path=storage_base)
        
        # Discover plugins and track stats for startup summary
        discovered = self.plugin_loader.discover_all()
        self._plugin_count = len(discovered)
        # Each plugin is one tool in Event Mill's architecture
        self._tool_count = self._plugin_count
        self._load_errors: list[str] = []
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
                self._load_errors.append(f"Router: {e}")
                logger.warning("Failed to initialize router: %s", e)
        
        # LLM availability - check for dual Gemini keys or legacy single key
        self._available_models: list[dict[str, str]] = []
        
        # Check for dual Gemini API keys (production setup)
        if os.environ.get("GEMINI_FLASH_API_KEY"):
            self._available_models.append({
                "id": "gemini-2.5-flash",
                "name": "Gemini Flash",
                "tier": "light",
                "env_var": "GEMINI_FLASH_API_KEY",
            })
        if os.environ.get("GEMINI_PRO_API_KEY"):
            self._available_models.append({
                "id": "gemini-2.5-pro",
                "name": "Gemini Pro",
                "tier": "heavy",
                "env_var": "GEMINI_PRO_API_KEY",
            })
        
        # Fallback: legacy single GEMINI_API_KEY
        if not self._available_models and os.environ.get("GEMINI_API_KEY"):
            self._available_models.append({
                "id": "gemini-2.5-flash",
                "name": "Gemini (default)",
                "tier": "default",
                "env_var": "GEMINI_API_KEY",
            })
        
        # Check for Anthropic
        if os.environ.get("ANTHROPIC_API_KEY"):
            self._available_models.append({
                "id": "claude-sonnet-4-20250514",
                "name": "Claude Sonnet",
                "tier": "heavy",
                "env_var": "ANTHROPIC_API_KEY",
            })
        
        self._llm_available = len(self._available_models) > 0
        
        self._update_prompt()
    
    def _update_prompt(self) -> None:
        """Update the command prompt based on current state."""
        session = self.session_manager.get_current_session()
        if session:
            pillar = session.active_pillar or "no-pillar"
            workspace = session.workspace_folder
            if workspace:
                self.prompt = f"eventmill ({pillar}:{workspace}) > "
            else:
                self.prompt = f"eventmill ({pillar}) > "
        else:
            self.prompt = "eventmill > "
    
    def preloop(self) -> None:
        """Display startup banner with summary stats."""
        # Random colored ASCII art banner (Metasploit-style)
        print(_random_banner())
        
        # Build startup summary
        lines = []
        
        # Plugin/tool summary
        if self._load_errors:
            lines.append(f"  ⚠ Loaded {self._plugin_count} plugins, {self._tool_count} tools ({len(self._load_errors)} errors)")
            for err in self._load_errors:
                lines.append(f"    - {err}")
        else:
            lines.append(f"  ✓ Loaded {self._plugin_count} plugins, {self._tool_count} tools")
        
        # LLM availability
        if self._llm_available:
            model_names = [m["name"] for m in self._available_models]
            lines.append(f"  ✓ LLM models available: {', '.join(model_names)}")
        else:
            lines.append("  ○ No LLM configured (set GEMINI_FLASH_API_KEY or GEMINI_PRO_API_KEY)")
        
        lines.append("")
        lines.append("  Type 'help' for available commands, 'new' to start a session.")
        lines.append("")
        
        print("\n".join(lines))
        
        # Log startup activity
        log_user_activity("shell_started", {
            "plugins_loaded": self._plugin_count,
            "tools_loaded": self._tool_count,
            "errors": len(self._load_errors),
            "llm_available": self._llm_available,
        })
    
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
        
        # Update user context for activity logging
        set_user_context(session_id=session.session_id)
        
        # Log activity
        log_user_activity("new_session", {
            "session_id": session.session_id,
            "description": description or None,
        })
        
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
            
            # Update user context for activity logging
            set_user_context(session_id=session.session_id)
            
            # Log activity
            log_user_activity("load_session", {
                "session_id": session.session_id,
                "pillar": session.active_pillar,
            })
            
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
        
        # Log activity
        log_user_activity("delete_session", {"session_id": session_id})
        
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
        
        # Log activity
        log_user_activity("set_pillar", {
            "pillar": pillar,
            "tools_available": len(tools),
        })
        
        print(f"  Pillar set to: {pillar} ({len(tools)} tools available)")
        self._update_prompt()
    
    # -------------------------------------------------------------------
    # Workspace Commands
    # -------------------------------------------------------------------
    
    def do_workspace(self, arg: str) -> None:
        """Set or show the active workspace folder.
        
        The workspace folder scopes file resolution to a subfolder within
        each storage bucket (e.g. an incident identifier).
        
        Usage:
            workspace                  — show current workspace
            workspace <folder_name>    — set workspace folder
            workspace clear            — clear workspace folder
        """
        if not self.session_manager.get_current_session():
            print("  No active session. Use 'new' to create one.")
            return
        
        folder = arg.strip()
        
        if not folder:
            # Show current workspace
            session = self.session_manager.get_current_session()
            if session.workspace_folder:
                print(f"  Workspace: {session.workspace_folder}")
            else:
                print("  No workspace folder set.")
                print("  Usage: workspace <folder_name>  (e.g. workspace incident-2024-03)")
            return
        
        if folder == "clear":
            self.session_manager.set_workspace(None)
            log_user_activity("clear_workspace")
            print("  Workspace folder cleared.")
        else:
            self.session_manager.set_workspace(folder)
            log_user_activity("set_workspace", {"workspace_folder": folder})
            print(f"  Workspace set to: {folder}")
        
        self._update_prompt()
    
    def do_buckets(self, arg: str) -> None:
        """Show configured storage buckets.
        
        Usage: buckets
        """
        if not self.storage_resolver:
            print("  Storage resolver not initialized.")
            return
        
        buckets = self.storage_resolver.describe_buckets()
        
        print(f"  {'Pillar':25s} {'Bucket':40s} Type")
        print(f"  {'─' * 25} {'─' * 40} {'─' * 10}")
        
        for b in buckets:
            print(f"  {b['pillar']:25s} {b['bucket']:40s} {b['type']}")

    def do_export(self, arg: str) -> None:
        """Export a session artifact to the common storage bucket.

        Writes to common/exports/<source_tool>/ by default — mirroring the
        common/generated/ convention used by threat_report_analyzer.  Intended
        for troubleshooting or handing off JSON/MMD outputs to external tools.
        Not required for normal in-container workflows.

        Usage: export <artifact_id> [subfolder]

        artifact_id — ID from the 'artifacts' command (e.g. art_04d30b48)
        subfolder   — Optional path appended inside exports/<source_tool>/.
                      Useful for tagging by incident (e.g. incident-2025-04).

        Destination layout:
          common/exports/<source_tool>/<filename>
          common/exports/<source_tool>/<subfolder>/<filename>   (with subfolder)

        Examples:
          export art_04d30b48
          export art_04d30b48 incident-2025-04
        """
        if not self.session_manager.get_current_session():
            print("  No active session. Use 'session new' first.")
            return

        if not self.storage_resolver:
            print("  Storage resolver not initialized.")
            return

        parts = shlex.split(arg) if arg.strip() else []
        if not parts:
            print("  Usage: export <artifact_id> [subfolder]")
            return

        artifact_id = parts[0]
        subfolder = parts[1] if len(parts) > 1 else None

        # Resolve artifact
        artifact = self.session_manager.get_artifact(artifact_id)
        if artifact is None:
            print(f"  Artifact '{artifact_id}' not found. Use 'artifacts' to list.")
            return

        local_path = Path(artifact.file_path)
        if not local_path.exists():
            print(f"  Artifact file missing on disk: {local_path}")
            return

        # Build destination folder: exports/<source_tool>[/<subfolder>]
        source_tool = getattr(artifact, "source_tool", None) or "unknown"
        dest_folder = f"exports/{source_tool}"
        if subfolder:
            dest_folder = f"{dest_folder}/{subfolder}"

        # Pillar is only needed by the resolver to name the pillar bucket;
        # since target="common" it won't be used for routing, but must be valid.
        session = self.session_manager.get_current_session()
        pillar = session.active_pillar or "log_analysis"

        filename = local_path.name
        common_bucket = self.storage_resolver.config.common_bucket()

        print(f"  Exporting {artifact_id} ({artifact.artifact_type})")
        print(f"  Destination: {common_bucket}/{dest_folder}/{filename}")

        try:
            resolved = self.storage_resolver.upload(
                local_path=local_path,
                filename=filename,
                pillar=pillar,
                workspace_folder=dest_folder,
                target="common",
                metadata={
                    "artifact_id": artifact_id,
                    "artifact_type": artifact.artifact_type,
                    "source_tool": source_tool,
                },
            )
            print(f"  ✓ Uploaded: {resolved.uri}")
            log_user_activity("export_artifact", {
                "artifact_id": artifact_id,
                "destination": resolved.uri,
                "source_tool": source_tool,
            })
        except Exception as e:
            print(f"  ✗ Export failed: {e}")
            logger.error("Artifact export failed: %s", e)

    def do_files(self, arg: str) -> None:
        """List files available in the current pillar's storage.
        
        Shows files from both the pillar bucket and the common bucket.
        If a workspace folder is set, lists files within that folder.
        
        Usage: files
        """
        session = self.session_manager.get_current_session()
        if not session:
            print("  No active session. Use 'new' to create one.")
            return
        
        if not session.active_pillar:
            print("  No pillar selected. Use 'pillar <name>' first.")
            return
        
        if not self.storage_resolver:
            print("  Storage resolver not initialized.")
            return
        
        files = self.storage_resolver.list_workspace(
            pillar=session.active_pillar,
            workspace_folder=session.workspace_folder,
        )
        
        if not files:
            location = session.active_pillar
            if session.workspace_folder:
                location += f"/{session.workspace_folder}"
            print(f"  No files found in {location} or common bucket.")
            return
        
        print(f"  {'Filename':40s} {'Source':10s} Path")
        print(f"  {'─' * 40} {'─' * 10} {'─' * 40}")
        
        for f in files:
            print(f"  {f['filename']:40s} {f['source']:10s} {f['object_path']}")
    
    # -------------------------------------------------------------------
    # Artifact Commands
    # -------------------------------------------------------------------
    
    def do_load(self, arg: str) -> None:
        """Load an artifact file into the current session.
        
        Usage: load <file_path_or_name> [artifact_type]
        
        Resolution order:
          1. Local file path (if exists on disk)
          2. Explicit gs:// URI
          3. Pillar bucket (workspace folder, then root)
          4. Common bucket (workspace folder, then root)
        
        Supported types: pcap, json_events, log_stream, risk_model,
        cloud_audit_log, pdf_report, html_report, image, text
        """
        if not self.session_manager.get_current_session():
            print("  No active session. Use 'new' to create one.")
            return
        
        try:
            parts = shlex.split(arg.strip())
        except ValueError:
            parts = arg.strip().split(maxsplit=1)
        if not parts:
            print("  Usage: load <file_path_or_name> [artifact_type]")
            return
        
        file_ref = parts[0]
        file_path = Path(file_ref)
        
        # Try local file first
        if file_path.exists():
            artifact_type = parts[1] if len(parts) > 1 else self._infer_artifact_type(file_path)
            self._register_local_artifact(file_path, artifact_type)
            return
        
        # Try storage resolver (gs:// URI or filename lookup in buckets)
        session = self.session_manager.get_current_session()
        if self.storage_resolver and session.active_pillar:
            explicit = file_ref if file_ref.startswith("gs://") else None
            filename = file_ref if not explicit else None
            
            resolved = self.storage_resolver.resolve(
                filename=filename or "",
                pillar=session.active_pillar,
                workspace_folder=session.workspace_folder,
                explicit_path=explicit,
            )
            
            if resolved:
                # Download to local workspace for tool access
                local_dest = (
                    self.workspace_path / "artifacts"
                    / session.session_id
                    / (resolved.object_path.rsplit("/", 1)[-1] if "/" in resolved.object_path else resolved.object_path)
                )
                local_dest.parent.mkdir(parents=True, exist_ok=True)
                
                try:
                    self.storage_resolver.download(resolved, local_dest)
                except Exception as e:
                    print(f"  Failed to download from {resolved.display}: {e}")
                    return
                
                artifact_type = parts[1] if len(parts) > 1 else self._infer_artifact_type(local_dest)
                self._register_local_artifact(local_dest, artifact_type, source_info=resolved.display)
                return
        
        # Nothing found
        print(f"  File not found: {file_ref}")
        if session.active_pillar and self.storage_resolver:
            print(f"  Searched: local path, {session.active_pillar} bucket, common bucket")
            if session.workspace_folder:
                print(f"  Workspace: {session.workspace_folder}")
        else:
            print("  Tip: set a pillar to enable bucket-based file resolution.")
    
    def _register_local_artifact(
        self,
        file_path: Path,
        artifact_type: str,
        source_info: str | None = None,
    ) -> None:
        """Register a local file as an artifact in the current session."""
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
        
        # Log activity
        log_user_activity("load_artifact", {
            "artifact_id": artifact.artifact_id,
            "artifact_type": artifact_type,
            "filename": file_path.name,
        })
        
        print(f"  Loaded artifact: {artifact.artifact_id}")
        print(f"  Type: {artifact_type}")
        print(f"  File: {file_path.name}")
        if source_info:
            print(f"  Source: {source_info}")
    
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
        
        print(f"  {'Display Name':30s} {'Invoke As':30s} {'Pillar':20s} {'Stability':12s} Description")
        print(f"  {'─' * 30} {'─' * 30} {'─' * 20} {'─' * 12} {'─' * 50}")
        
        for p in plugins:
            m = p.manifest
            desc = m.description_short[:80] if m.description_short else "—"
            invoke = f"run {m.tool_name}"
            print(f"  {m.display_name:30s} {invoke:30s} {m.pillar:20s} {m.stability:12s} {desc}")
    
    def do_help(self, arg: str) -> None:
        """Show help for a command or tool.

        Usage: help [command_or_tool_name]

        For tool-specific usage, pass the tool name:
          help threat_report_analyzer
        """
        if arg:
            plugin = self.plugin_loader.get(arg.strip())
            if plugin:
                self._print_tool_help(plugin)
                return
        super().do_help(arg)

    def _print_tool_help(self, plugin: LoadedPlugin) -> None:
        """Print help for a tool by rendering its README.md."""
        m = plugin.manifest
        readme_path = m.plugin_dir / "README.md"

        print()
        print(f"  {'─' * 60}")
        print(f"  {m.display_name}  ({m.tool_name})")
        print(f"  Pillar: {m.pillar}   Stability: {m.stability}")
        print(f"  Invoke: run {m.tool_name} {{\"action\": \"...\"}}") 
        print(f"  {'─' * 60}")
        print()

        if readme_path.exists():
            rendered = self._render_markdown_plain(readme_path.read_text(encoding="utf-8"))
            print(rendered)
        else:
            print(f"  {m.description_short}")
            print()
            print("  No README.md available for this tool.")
        print()

    @staticmethod
    def _render_markdown_plain(text: str) -> str:
        """Convert Markdown to readable plain-text for terminal display."""
        import re
        import textwrap

        lines = text.splitlines()
        out: list[str] = []
        in_code = False

        for line in lines:
            # Toggle fenced code block
            if line.startswith("```"):
                in_code = not in_code
                if in_code:
                    out.append("")
                else:
                    out.append("")
                continue

            if in_code:
                out.append(f"    {line}")
                continue

            # H1
            if line.startswith("# "):
                title = line[2:].strip()
                out.append(f"\n  {title}")
                out.append(f"  {'═' * len(title)}")
                continue
            # H2
            if line.startswith("## "):
                title = line[3:].strip()
                out.append(f"\n  {title}")
                out.append(f"  {'─' * len(title)}")
                continue
            # H3
            if line.startswith("### "):
                title = line[4:].strip()
                out.append(f"\n  {title}:")
                continue

            # Strip inline bold/italic/code markers
            line = re.sub(r"\*\*(.+?)\*\*", r"\1", line)
            line = re.sub(r"\*(.+?)\*", r"\1", line)
            line = re.sub(r"`(.+?)`", r"\1", line)

            # Table separator rows — skip
            if re.match(r"^\|[-| :]+\|$", line.strip()):
                continue

            # Table rows and list items — indent and pass through
            if line.startswith("|") or line.startswith("- ") or line.startswith("* ") or re.match(r"^\d+\. ", line):
                out.append(f"  {line}")
                continue

            # Blank lines
            if not line.strip():
                out.append("")
                continue

            # Paragraph text — word-wrap at 78
            wrapped = textwrap.fill(
                line, width=78, initial_indent="  ", subsequent_indent="  "
            )
            out.append(wrapped)

        return "\n".join(out)

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
        
        # Resolve artifact_id → file_path for plugins that need a file
        if "artifact_id" in payload:
            art_path = self.session_manager.get_artifact_path(payload["artifact_id"])
            if art_path is None:
                print(f"  Artifact not found: {payload['artifact_id']}")
                return
            # Inject file_path (most plugins) and path (log_navigator)
            # Keep artifact_id — plugins using registry lookup still need it
            payload.setdefault("file_path", str(art_path))
            payload.setdefault("path", str(art_path))
        
        # Get plugin instance
        instance = plugin.get_instance()
        
        # Validate inputs
        validation = instance.validate_inputs(payload)
        if not validation.ok:
            print(f"  Input validation failed:")
            for error in (validation.errors or []):
                print(f"    - {error}")
            return
        
        # Snapshot registered artifacts before execution to detect new ones afterwards
        _artifacts_before = {a.artifact_id for a in self.session_manager.list_artifacts()}

        # Build execution context
        session = self.session_manager.get_current_session()
        # Session artifacts carry the user-visible IDs shown by 'artifacts' command
        artifact_refs = [
            ArtifactRef(
                artifact_id=sa.artifact_id,
                artifact_type=sa.artifact_type,
                file_path=sa.file_path,
                source_tool=getattr(sa, "source_tool", None),
                metadata=getattr(sa, "metadata", None) or {},
            )
            for sa in self.session_manager.list_artifacts()
        ]
        # Append tool-produced artifacts from registry that aren't already present
        if self.artifact_registry:
            existing_ids = {a.artifact_id for a in artifact_refs}
            for ra in self.artifact_registry.list_all():
                if ra.artifact_id not in existing_ids:
                    artifact_refs.append(ra)
        
        def _register_artifact(
            artifact_type: str,
            file_path: str,
            source_tool: str,
            metadata: dict,
        ) -> ArtifactRef:
            """Persist tool-produced artifacts in session_manager (visible in 'artifacts') and return a canonical ArtifactRef."""
            session_art = self.session_manager.register_artifact(
                artifact_type=artifact_type,
                file_path=str(file_path),
                source_tool=source_tool,
                metadata=metadata or {},
            )
            return ArtifactRef(
                artifact_id=session_art.artifact_id,
                artifact_type=session_art.artifact_type,
                file_path=str(file_path),
                source_tool=source_tool,
                metadata=metadata or {},
            )

        context = ExecutionContext(
            session_id=session.session_id,
            selected_pillar=session.active_pillar or "",
            artifacts=artifact_refs,
            llm_enabled=self.llm_client is not None and self.llm_client.connected,
            llm_query=self.llm_client,
            register_artifact=_register_artifact,
            reference_data=ReferenceDataView(),
        )
        
        # Track execution
        execution = self.session_manager.start_execution(
            tool_name=tool_name,
        )
        
        timeout = TimeoutClass.get_limit(plugin.manifest.timeout_class)
        print(f"  Running {plugin.manifest.display_name} (timeout {timeout}s)...")
        
        try:
            # Execute with thread-based timeout to prevent indefinite hangs
            _result_holder: list = [None]
            _error_holder: list = [None]

            def _run_plugin():
                try:
                    _result_holder[0] = instance.execute(payload, context)
                except Exception as exc:
                    _error_holder[0] = exc

            worker = threading.Thread(target=_run_plugin, daemon=True)
            worker.start()

            # Poll with a visible elapsed-time ticker instead of a single
            # silent join.  The periodic output also keeps the WebSocket
            # alive through Cloud Run's load-balancer.
            _tick = 10  # seconds between progress updates
            _elapsed = 0
            while _elapsed < timeout:
                worker.join(timeout=min(_tick, timeout - _elapsed))
                _elapsed += _tick
                if not worker.is_alive():
                    break
                print(f"  \u23f3 {_elapsed}s / {timeout}s ...", flush=True)

            if worker.is_alive():
                print(f"  \u2718 Timed out after {timeout}s")
                self.session_manager.complete_execution(
                    execution=execution,
                    status=ToolExecutionStatus.FAILED,
                    summary=f"Execution timed out after {timeout}s",
                )
                log_user_activity("run_tool", {
                    "tool_name": tool_name,
                    "execution_id": execution.execution_id,
                    "status": "timeout",
                })
                return

            if _error_holder[0] is not None:
                raise _error_holder[0]

            result = _result_holder[0]
            if result is None:
                raise RuntimeError("Plugin returned None instead of ToolResult")
            
            if result.ok:
                # Auto-persist output if the tool didn't register an artifact itself
                _artifacts_after = {a.artifact_id for a in self.session_manager.list_artifacts()}
                if not (_artifacts_after - _artifacts_before) and result.result is not None:
                    self._auto_persist_result(
                        result=result,
                        tool_name=tool_name,
                        artifacts_produced=getattr(plugin.manifest, "artifacts_produced", []) or [],
                    )

                summary = instance.summarize_for_llm(result)
                self.session_manager.complete_execution(
                    execution=execution,
                    status=ToolExecutionStatus.COMPLETED,
                    summary=summary,
                )
                
                # Log activity
                log_user_activity("run_tool", {
                    "tool_name": tool_name,
                    "execution_id": execution.execution_id,
                    "status": "completed",
                })
                
                print(f"  ✓ Completed successfully")
                print(f"\n  Summary:\n  {summary}")
            else:
                self.session_manager.complete_execution(
                    execution=execution,
                    status=ToolExecutionStatus.FAILED,
                    summary=result.message or "",
                )
                
                # Log activity
                log_user_activity("run_tool", {
                    "tool_name": tool_name,
                    "execution_id": execution.execution_id,
                    "status": "failed",
                    "error_code": str(result.error_code),
                })
                
                print(f"  ✗ Failed: {result.error_code}")
                if result.message:
                    print(f"    {result.message}")
                    
        except Exception as e:
            self.session_manager.complete_execution(
                execution=execution,
                status=ToolExecutionStatus.FAILED,
                summary=str(e),
            )
            
            # Log activity
            log_user_activity("run_tool", {
                "tool_name": tool_name,
                "execution_id": execution.execution_id,
                "status": "error",
                "error": str(e),
            })
            
            print(f"  ✗ Error: {e}")
            logger.exception("Tool execution failed: %s", tool_name)

    def _auto_persist_result(
        self,
        result: Any,
        tool_name: str,
        artifacts_produced: list[str],
    ) -> None:
        """Write a tool's ToolResult.result to disk and register it with the session.

        Called when a tool completes successfully but did not call
        context.register_artifact() itself.  Produces a single output artifact
        whose type is taken from the first entry of the manifest's
        artifacts_produced list (defaulting to 'json_events').

        Text-oriented tools (artifact_type == 'text') receive a .md file whose
        content is the first string field found among common display keys
        (visualization, content, summary, analysis, report, output).
        All other tools receive a .json file containing the full result dict.
        """
        workspace = Path(os.environ.get("EVENTMILL_WORKSPACE", "./workspace"))
        output_dir = workspace / "artifacts"
        output_dir.mkdir(parents=True, exist_ok=True)

        artifact_type = artifacts_produced[0] if artifacts_produced else "json_events"
        result_data = result.result or {}
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Choose format: markdown for text artifacts, JSON for everything else
        if artifact_type == "text":
            text_content: str | None = None
            for key in ("visualization", "content", "summary", "analysis", "report", "output"):
                val = result_data.get(key)
                if isinstance(val, str) and val.strip():
                    text_content = val
                    break
            if text_content is None:
                text_content = json.dumps(result_data, indent=2, default=str)
            content = text_content
            ext = ".md"
        else:
            content = json.dumps(result_data, indent=2, default=str)
            ext = ".json"

        filename = f"{tool_name}_{ts}{ext}"
        output_file = output_dir / filename

        try:
            output_file.write_text(content, encoding="utf-8")
            session_art = self.session_manager.register_artifact(
                artifact_type=artifact_type,
                file_path=str(output_file),
                source_tool=tool_name,
                metadata={"auto_persisted": True},
            )
            logger.info(
                "Auto-persisted output for %s → %s (%s)",
                tool_name, session_art.artifact_id, artifact_type,
            )
        except Exception as exc:
            logger.warning("Auto-persist failed for %s: %s", tool_name, exc)

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
        print(f"  Workspace:  {session.workspace_folder or '—'}")
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
    
    def do_models(self, arg: str) -> None:
        """List available LLM models.
        
        Usage: models
        """
        if not self._available_models:
            print("  No LLM models configured.")
            print("  Set GEMINI_FLASH_API_KEY and/or GEMINI_PRO_API_KEY environment variables.")
            return
        
        print(f"  {'Model':20s} {'Tier':10s} {'Status':14s} {'ID':30s}")
        print(f"  {'─' * 20} {'─' * 10} {'─' * 14} {'─' * 30}")
        
        for model in self._available_models:
            status = self._model_connected_status(model)
            print(f"  {model['name']:20s} {model['tier']:10s} {status:14s} {model['id']:30s}")
        
        print("")
        print("  'connect'            — bind all models (tiered auto-routing)")
        print("  'connect <model_id>' — bind a specific model only")
        print(f"  Routing: max_tokens ≤ {TieredLLMClient.LIGHT_THRESHOLD} → light (Flash), > {TieredLLMClient.LIGHT_THRESHOLD} → heavy (Pro)")
    
    def do_connect(self, arg: str) -> None:
        """Connect to LLM.
        
        Usage: connect [model_id]
        
        If no model_id specified, uses the first available model.
        Use 'models' command to see available models.
        """
        if not self._available_models:
            print("  No LLM models configured.")
            print("  Set GEMINI_FLASH_API_KEY and/or GEMINI_PRO_API_KEY environment variables.")
            return
        
        model_id = arg.strip()
        transport = os.environ.get("EVENTMILL_MCP_TRANSPORT", "stdio")
        
        if not model_id:
            # No model specified — connect ALL available models as a tiered pair
            connected_clients: dict[str, MCPLLMClient] = {}
            failed: list[str] = []

            for m in self._available_models:
                api_key = os.environ.get(m["env_var"])
                if not api_key:
                    failed.append(f"  ✗ {m['name']}: {m['env_var']} not set")
                    continue
                client = MCPLLMClient(model_id=m["id"], transport=transport)
                client._api_key_env_var = m["env_var"]
                if client.connect(api_key=api_key):
                    connected_clients[m["tier"]] = client
                    print(f"  ✓ {m['name']} ({m['id']})")
                    print(f"    Tier: {m['tier']}")
                else:
                    failed.append(f"  ✗ {m['name']}: connection failed — check API key and google-generativeai install")

            for msg in failed:
                print(msg)

            if not connected_clients:
                print("  No models connected.")
                return

            self.llm_client = TieredLLMClient(clients=connected_clients)

            log_user_activity("connect_llm", {
                "models": {tier: c.model_id for tier, c in connected_clients.items()},
                "tiered": True,
            })

            if len(connected_clients) > 1:
                print(f"")
                print(f"  Auto-routing: max_tokens ≤ {TieredLLMClient.LIGHT_THRESHOLD} → light, "
                      f"> {TieredLLMClient.LIGHT_THRESHOLD} → heavy")
            return

        # Specific model requested — single-client mode
        selected_model = None
        for m in self._available_models:
            if m["id"] == model_id or m["name"].lower() == model_id.lower():
                selected_model = m
                break
        if not selected_model:
            print(f"  Model not found: {model_id}")
            print("  Use 'models' to see available models.")
            return

        api_key = os.environ.get(selected_model["env_var"])
        if not api_key:
            print(f"  API key not found in {selected_model['env_var']}")
            return

        self.llm_client = MCPLLMClient(
            model_id=selected_model["id"],
            transport=transport,
        )
        self.llm_client._api_key_env_var = selected_model["env_var"]

        if not self.llm_client.connect(api_key=api_key):
            print(f"  ✗ Failed to connect to {selected_model['name']}")
            print("    Check that google-generativeai is installed and the API key is valid.")
            self.llm_client = None
            return

        log_user_activity("connect_llm", {
            "model_id": selected_model["id"],
            "model_name": selected_model["name"],
            "tier": selected_model["tier"],
        })

        print(f"  ✓ Connected to {selected_model['name']} ({selected_model['id']})")
        print(f"    Tier: {selected_model['tier']}")
    
    def do_ask(self, arg: str) -> None:
        """Ask a question about the current investigation using the connected LLM.
        
        Usage: ask: <question>
        
        The colon after 'ask' is required — it signals conscious intent
        to invoke the LLM (which costs tokens and time).
        
        The LLM receives full context from your session: loaded artifacts,
        all tool execution summaries, and prior conversation turns.
        
        Examples:
          ask: what were the usernames targeted in this log file?
          ask: summarize the threat findings so far
          ask: root login is disabled on this server — re-evaluate the threat rating
          ask: search the internet for CVEs related to this SSH pattern
        """
        # Require the colon prefix for conscious intent
        if not arg.startswith(":"):
            print("  Usage: ask: <question>")
            print("  The colon is required to confirm LLM intent.")
            return
        
        question = arg[1:].strip()
        if not question:
            print("  Usage: ask: <question>")
            return
        
        self._query_llm(question)
    
    def _query_llm(self, question: str) -> None:
        """Send a contextual question to the connected LLM and print the response."""
        if not self.llm_client or not self.llm_client.connected:
            print("  No LLM connected. Use 'connect <model_id>' first.")
            print("  Use 'models' to see available models.")
            return
        
        session = self.session_manager.get_current_session()
        if not session:
            print("  No active session. Use 'new' to create one.")
            return
        
        # Build grounding context from session state
        context_parts = self._build_conversation_context(session)
        
        # Include conversation history (last 10 turns)
        history_text = ""
        if self._conversation_history:
            recent = self._conversation_history[-10:]
            history_lines = []
            for turn in recent:
                history_lines.append(f"Analyst: {turn['question']}")
                history_lines.append(f"AI: {turn['answer']}\n")
            history_text = "\n".join(history_lines)
        
        system_context = (
            "You are a Tier 3 SOC analyst assistant embedded in Event Mill, "
            "an event record analysis platform. You have access to the "
            "investigation context below including loaded artifacts and "
            "prior tool execution results. Answer the analyst's questions "
            "thoroughly and specifically based on the evidence available. "
            "When the analyst provides new information (e.g. 'root login is "
            "disabled'), incorporate it to refine your threat assessment. "
            "Reference specific log patterns, IPs, usernames, and counts "
            "from the execution summaries when available. "
            "If asked to search for information or CVEs, use your training "
            "knowledge to provide the most relevant known information."
        )
        
        # Assemble the full prompt
        prompt_parts = []
        if context_parts:
            prompt_parts.append("=== INVESTIGATION CONTEXT ===")
            prompt_parts.append(context_parts)
        if history_text:
            prompt_parts.append("=== CONVERSATION HISTORY ===")
            prompt_parts.append(history_text)
        prompt_parts.append("=== ANALYST QUESTION ===")
        prompt_parts.append(question)
        
        full_prompt = "\n\n".join(prompt_parts)
        
        print("  Thinking...")
        
        try:
            response = self.llm_client.query_text(
                prompt=full_prompt,
                system_context=system_context,
                max_tokens=4096,
            )
            
            if response.ok and response.text:
                # Store in conversation history
                self._conversation_history.append({
                    "question": question,
                    "answer": response.text,
                })
                
                # Print the response with indentation
                print("")
                for line in response.text.splitlines():
                    print(f"  {line}")
                print("")
                
                # Show token usage if available
                if response.token_usage:
                    total = response.token_usage.get("total_tokens", 0)
                    if total:
                        print(f"  [{total} tokens used]")
                
                # Log LLM interaction
                log_llm_interaction(
                    prompt=question,
                    response_text=response.text,
                    model_id=self.llm_client.model_id,
                    history_turns=len(self._conversation_history),
                )
            else:
                error = response.error or "Unknown error"
                print(f"  ✗ LLM query failed: {error}")
                log_llm_interaction(
                    prompt=question,
                    response_text=None,
                    model_id=self.llm_client.model_id,
                    history_turns=len(self._conversation_history),
                    error=error,
                )
                
        except Exception as e:
            print(f"  ✗ Error: {e}")
            logger.error("LLM query error: %s", e, exc_info=True)
            log_llm_interaction(
                prompt=question,
                response_text=None,
                model_id=self.llm_client.model_id if self.llm_client else None,
                history_turns=len(self._conversation_history),
                error=str(e),
            )
    
    def _build_conversation_context(self, session) -> str:
        """Assemble investigation context from session state for LLM grounding."""
        parts = []
        
        # Session info
        pillar = session.active_pillar or "none"
        workspace = session.workspace_folder or "default"
        parts.append(f"Session: {session.session_id}")
        parts.append(f"Pillar: {pillar}")
        parts.append(f"Workspace: {workspace}")
        
        # Loaded artifacts
        try:
            artifacts = self.session_manager.list_artifacts()
            if artifacts:
                parts.append("\n--- Loaded Artifacts ---")
                for art in artifacts:
                    fname = art.metadata.get("original_filename", art.file_path)
                    parts.append(f"  [{art.artifact_id}] {art.artifact_type}: {fname}")
        except ValueError:
            pass
        
        # All tool execution summaries (most important context)
        try:
            executions = self.session_manager.list_executions()
            completed = [e for e in executions if e.summary]
            if completed:
                parts.append("\n--- Tool Execution Results ---")
                for ex in completed:
                    parts.append(f"\n[{ex.tool_name}] ({ex.started_at.strftime('%H:%M')}):")
                    parts.append(ex.summary)
        except ValueError:
            pass
        
        return "\n".join(parts)
    
    def do_history(self, arg: str) -> None:
        """Show conversation history with the LLM.
        
        Usage: history [clear]
        """
        if arg.strip() == "clear":
            self._conversation_history.clear()
            print("  Conversation history cleared.")
            return
        
        if not self._conversation_history:
            print("  No conversation history. Use 'ask <question>' to start.")
            return
        
        for i, turn in enumerate(self._conversation_history, 1):
            q = turn["question"]
            a_preview = turn["answer"][:120] + "..." if len(turn["answer"]) > 120 else turn["answer"]
            print(f"  [{i}] Q: {q}")
            print(f"      A: {a_preview}")
            print()
    
    def do_exit(self, arg: str) -> bool:
        """Exit Event Mill.
        
        Usage: exit
        """
        # Log activity
        log_user_activity("shell_exit")
        
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
        if self.llm_client and self.llm_client.connected:
            print("  Tip: use 'ask: <question>' to query the LLM.")
    
    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------
    
    def _model_connected_status(self, model: dict) -> str:
        """Return a short status string for a model entry in 'models' output."""
        if self.llm_client is None:
            return ""
        if isinstance(self.llm_client, TieredLLMClient):
            c = self.llm_client._clients.get(model["tier"])
            return "✓ connected" if (c and c.connected) else ""
        if isinstance(self.llm_client, MCPLLMClient):
            return "✓ connected" if (self.llm_client.model_id == model["id"] and self.llm_client.connected) else ""
        return ""

    def _infer_artifact_type(self, file_path: Path) -> str:
        """Infer artifact type from file extension.
        
        Handles rotated log files (e.g. auth.log.1, syslog.2.gz) by
        walking the suffix chain from right to left until a known
        extension is found.
        """
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
            ".md": "text",
            ".markdown": "text",
            ".docx": "docx_report",
            ".doc": "docx_report",
            ".png": "image",
            ".jpg": "image",
            ".jpeg": "image",
            ".gif": "image",
            ".bmp": "image",
        }
        
        # Walk suffixes right-to-left: .log.1 → try ".1" then ".log"
        for ext in reversed(file_path.suffixes):
            mapped = type_map.get(ext.lower())
            if mapped:
                return mapped
        
        return "text"


def main() -> None:
    """Entry point for the Event Mill CLI."""
    # Setup logging
    log_level = os.environ.get("EVENTMILL_LOG_LEVEL", "INFO")
    workspace = Path(
        os.environ.get("EVENTMILL_WORKSPACE", "./workspace")
    )
    log_file = workspace / "logs" / "eventmill.log"
    
    # Cloud Run sets K_SERVICE env var — use JSON logging for Cloud Logging
    is_cloud_run = os.environ.get("K_SERVICE") is not None
    
    setup_logging(
        log_level=log_level,
        log_file=log_file,
        console=True,
        cloud_json=is_cloud_run,
    )
    
    # Gracefully handle SIGHUP (signal 1) — sent by ttyd when a browser
    # tab closes or Cloud Run manages instance lifecycle. Without this,
    # the Python process crashes with "Uncaught signal: 1".
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, lambda signum, frame: sys.exit(0))
    
    try:
        shell = EventMillShell()
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\n  Interrupted. Goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()
