"""
Event Mill LLM Client

MCP-based LLM client that implements the LLMQueryInterface protocol.
The framework owns the MCP connection; plugins access LLM via this client.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from ..plugins.protocol import LLMQueryInterface, LLMResponse

try:
    from google import genai
    from google.genai import types as genai_types
    _HAS_GENAI = True
except ImportError:
    _HAS_GENAI = False

logger = logging.getLogger("eventmill.framework.llm")


class MCPLLMClient:
    """LLM client communicating via Model Context Protocol.
    
    This is the framework's LLM integration point. Plugins receive
    a reference to this client via ExecutionContext.llm_query.
    
    The client abstracts away the specific model provider (Gemini, Claude,
    GPT, etc.) behind the MCP transport layer.
    """
    
    def __init__(
        self,
        model_id: str = "gemini-2.5-flash",
        transport: str = "stdio",
        endpoint: str | None = None,
        max_retries: int = 2,
    ):
        """Initialize MCP LLM client.
        
        Args:
            model_id: Model identifier for the LLM provider.
            transport: MCP transport type (stdio or sse).
            endpoint: Provider endpoint URL (if applicable).
            max_retries: Maximum retry attempts for failed queries.
        """
        self.model_id = model_id
        self.transport = transport
        self.endpoint = endpoint
        self.max_retries = max_retries
        self._connected = False
        self._mcp_session = None
        self._genai_client = None
        self._api_key_env_var: str | None = None
        self._total_tokens_used = 0
    
    @property
    def connected(self) -> bool:
        """Whether the client is connected to the MCP server."""
        return self._connected
    
    @property
    def total_tokens_used(self) -> int:
        """Total tokens consumed across all queries in this session."""
        return self._total_tokens_used
    
    def connect(self, api_key: str | None = None) -> bool:
        """Establish connection to the LLM provider.
        
        Args:
            api_key: API key for the provider. If None, uses the
                     key from the environment variable set during init.
        
        Returns:
            True if connection succeeded.
        """
        if not _HAS_GENAI:
            logger.error("google-generativeai package not installed")
            self._connected = False
            return False
        
        resolved_key = api_key or os.environ.get(self._api_key_env_var or "", "")
        if not resolved_key:
            logger.error("No API key available for %s", self.model_id)
            self._connected = False
            return False
        
        try:
            self._genai_client = genai.Client(api_key=resolved_key)
            self._connected = True
            logger.info(
                "Connected to %s via Google GenAI SDK", self.model_id,
            )
            return True
        except Exception as e:
            logger.error("Failed to connect to %s: %s", self.model_id, e)
            self._connected = False
            return False
    
    async def disconnect(self) -> None:
        """Close MCP connection."""
        if self._mcp_session:
            # Close MCP session
            pass
        self._connected = False
        logger.info("Disconnected from MCP")
    
    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        grounding_data: list[str] | None = None,
    ) -> LLMResponse:
        """Send a text prompt to the LLM via MCP.
        
        Args:
            prompt: The user prompt.
            system_context: Optional system context override.
            max_tokens: Maximum tokens in response.
            grounding_data: Additional context strings.
        
        Returns:
            LLMResponse with text or error.
        """
        if not self._connected:
            return LLMResponse(
                ok=False,
                error="MCP connection not established",
            )
        
        # Build the full prompt with grounding data
        full_prompt = self._build_prompt(prompt, grounding_data)
        
        logger.debug(
            "LLM query: %d chars prompt, max_tokens=%d",
            len(full_prompt),
            max_tokens,
        )
        
        try:
            # MCP query execution will be implemented when
            # the mcp package is integrated. For now, return
            # a placeholder indicating the query would be sent.
            response_text = self._execute_mcp_query(
                prompt=full_prompt,
                system_context=system_context,
                max_tokens=max_tokens,
            )
            
            return LLMResponse(
                ok=True,
                text=response_text,
                token_usage={"prompt_tokens": 0, "completion_tokens": 0},
            )
        except Exception as e:
            logger.error("LLM query failed: %s", e)
            return LLMResponse(
                ok=False,
                error=str(e),
            )
    
    def query_multimodal(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send a multimodal prompt to the LLM via MCP.
        
        Args:
            prompt: The text prompt.
            image_data: Raw image bytes.
            image_format: Image format (jpeg, png).
            system_context: Optional system context.
            max_tokens: Maximum tokens in response.
        
        Returns:
            LLMResponse with text or error.
        """
        if not self._connected:
            return LLMResponse(
                ok=False,
                error="MCP connection not established",
            )
        
        logger.debug(
            "Multimodal LLM query: %d chars prompt, %d bytes image (%s)",
            len(prompt),
            len(image_data),
            image_format,
        )
        
        try:
            response_text = self._execute_mcp_multimodal_query(
                prompt=prompt,
                image_data=image_data,
                image_format=image_format,
                system_context=system_context,
                max_tokens=max_tokens,
            )
            
            return LLMResponse(
                ok=True,
                text=response_text,
                token_usage={"prompt_tokens": 0, "completion_tokens": 0},
            )
        except Exception as e:
            logger.error("Multimodal LLM query failed: %s", e)
            return LLMResponse(
                ok=False,
                error=str(e),
            )
    
    def _build_prompt(
        self,
        prompt: str,
        grounding_data: list[str] | None,
    ) -> str:
        """Build full prompt with grounding data prefix."""
        parts = []
        
        if grounding_data:
            parts.append("--- Context ---")
            for i, data in enumerate(grounding_data, 1):
                parts.append(f"[Context {i}]")
                parts.append(data)
            parts.append("--- End Context ---\n")
        
        parts.append(prompt)
        return "\n".join(parts)
    
    def _execute_mcp_query(
        self,
        prompt: str,
        system_context: str | None,
        max_tokens: int,
    ) -> str:
        """Execute a text query via Google GenAI SDK (MCP bridge).
        
        Uses google.genai directly until full MCP transport
        is integrated.
        """
        if self._genai_client is None:
            raise RuntimeError("Client not initialised — call connect() first")
        
        config = genai_types.GenerateContentConfig(
            max_output_tokens=max_tokens,
        )
        if system_context:
            config.system_instruction = system_context
        
        response = self._genai_client.models.generate_content(
            model=self.model_id,
            contents=prompt,
            config=config,
        )
        
        text = response.text or ""
        
        # Track token usage if available
        if hasattr(response, "usage_metadata") and response.usage_metadata:
            um = response.usage_metadata
            self._total_tokens_used += getattr(um, "total_token_count", 0)
        
        return text
    
    def _execute_mcp_multimodal_query(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None,
        max_tokens: int,
    ) -> str:
        """Execute a multimodal query via Google GenAI SDK (MCP bridge)."""
        if self._genai_client is None:
            raise RuntimeError("Client not initialised — call connect() first")
        
        mime_map = {"jpeg": "image/jpeg", "jpg": "image/jpeg", "png": "image/png"}
        mime_type = mime_map.get(image_format.lower(), f"image/{image_format}")
        
        config = genai_types.GenerateContentConfig(
            max_output_tokens=max_tokens,
        )
        if system_context:
            config.system_instruction = system_context
        
        contents = [
            prompt,
            genai_types.Part.from_bytes(data=image_data, mime_type=mime_type),
        ]
        
        response = self._genai_client.models.generate_content(
            model=self.model_id,
            contents=contents,
            config=config,
        )
        
        return response.text or ""


class TieredLLMClient:
    """Routes LLM queries to Flash (light) or Pro (heavy) automatically.

    When the user runs ``connect`` with no arguments, the shell creates one of
    these wrapping all available models.  Plugins call ``query_text`` exactly
    as before — the tier is selected transparently based on ``max_tokens``:

        max_tokens <= LIGHT_THRESHOLD  →  light / Flash  (fast, cheap)
        max_tokens >  LIGHT_THRESHOLD  →  heavy / Pro    (powerful, expensive)

    If the preferred tier is not connected the other tier is used as fallback.
    """

    LIGHT_THRESHOLD: int = 3500

    def __init__(self, clients: dict[str, MCPLLMClient]) -> None:
        self._clients = clients

    # --- Protocol compatibility -------------------------------------------------

    @property
    def connected(self) -> bool:
        return any(c.connected for c in self._clients.values())

    @property
    def model_id(self) -> str:
        parts = [c.model_id for tier in ("light", "heavy")
                 if (c := self._clients.get(tier)) and c.connected]
        return " + ".join(parts) if parts else "disconnected"

    @property
    def total_tokens_used(self) -> int:
        return sum(c.total_tokens_used for c in self._clients.values())

    def connected_models(self) -> list[dict[str, str]]:
        return [{"tier": tier, "model_id": c.model_id}
                for tier, c in self._clients.items() if c.connected]

    # --- Routing ---------------------------------------------------------------

    def _route(self, max_tokens: int) -> MCPLLMClient:
        """Select the appropriate client for the given output token budget."""
        prefer_heavy = max_tokens > self.LIGHT_THRESHOLD
        order = ("heavy", "light") if prefer_heavy else ("light", "heavy")
        for tier in order:
            c = self._clients.get(tier)
            if c and c.connected:
                return c
        raise RuntimeError("No LLM client connected — run 'connect' first")

    # --- LLMQueryInterface methods ---------------------------------------------

    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        grounding_data: list[str] | None = None,
    ) -> LLMResponse:
        try:
            client = self._route(max_tokens)
        except RuntimeError as e:
            return LLMResponse(ok=False, error=str(e))
        return client.query_text(
            prompt=prompt,
            system_context=system_context,
            max_tokens=max_tokens,
            grounding_data=grounding_data,
        )

    def query_multimodal(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        try:
            client = self._route(max_tokens)
        except RuntimeError as e:
            return LLMResponse(ok=False, error=str(e))
        return client.query_multimodal(
            prompt=prompt,
            image_data=image_data,
            image_format=image_format,
            system_context=system_context,
            max_tokens=max_tokens,
        )


class ContextBuilder:
    """Builds optimized LLM context from session state.
    
    This is a critical component for Event Mill's LLM context
    optimization strategy. It assembles the minimal context needed
    for each LLM interaction.
    """
    
    def __init__(
        self,
        system_identity: str = "",
        max_context_chars: int = 8000,
    ):
        """Initialize context builder.
        
        Args:
            system_identity: Base system identity prompt.
            max_context_chars: Maximum characters in assembled context.
        """
        self.system_identity = system_identity
        self.max_context_chars = max_context_chars
    
    def build_routing_context(
        self,
        pillar: str,
        tool_descriptions: list[dict[str, str]],
        recent_summaries: list[str],
    ) -> str:
        """Build context for routing decisions.
        
        Args:
            pillar: Active pillar name.
            tool_descriptions: Short descriptions of available tools.
            recent_summaries: Recent tool execution summaries.
        
        Returns:
            Assembled context string.
        """
        parts = []
        
        if self.system_identity:
            parts.append(self.system_identity)
        
        parts.append(f"\nActive investigation pillar: {pillar}")
        
        if tool_descriptions:
            parts.append("\nAvailable tools:")
            for tool in tool_descriptions:
                parts.append(
                    f"  - {tool['name']}: {tool['description']}"
                )
        
        if recent_summaries:
            parts.append("\nRecent analysis results:")
            for summary in recent_summaries:
                parts.append(f"  {summary}")
        
        context = "\n".join(parts)
        return self._truncate(context)
    
    def build_execution_context(
        self,
        tool_name: str,
        tool_description: str,
        user_input: str,
        artifact_summaries: list[str],
        recent_summaries: list[str],
    ) -> str:
        """Build context for tool execution.
        
        Args:
            tool_name: Name of the tool being executed.
            tool_description: Tool's description.
            user_input: The user's original request.
            artifact_summaries: Summaries of loaded artifacts.
            recent_summaries: Recent tool execution summaries.
        
        Returns:
            Assembled context string.
        """
        parts = []
        
        parts.append(f"Executing tool: {tool_name}")
        parts.append(f"Purpose: {tool_description}")
        parts.append(f"\nUser request: {user_input}")
        
        if artifact_summaries:
            parts.append("\nLoaded artifacts:")
            for summary in artifact_summaries:
                parts.append(f"  {summary}")
        
        if recent_summaries:
            parts.append("\nPrior analysis context:")
            for summary in recent_summaries:
                parts.append(f"  {summary}")
        
        context = "\n".join(parts)
        return self._truncate(context)
    
    def build_conversational_context(
        self,
        pillar: str,
        recent_summaries: list[str],
        artifact_count: int,
        user_input: str,
    ) -> str:
        """Build context for conversational interactions.
        
        Args:
            pillar: Active pillar.
            recent_summaries: Recent tool execution summaries.
            artifact_count: Number of loaded artifacts.
            user_input: The user's message.
        
        Returns:
            Assembled context string.
        """
        parts = []
        
        if self.system_identity:
            parts.append(self.system_identity)
        
        parts.append(f"\nInvestigation state: pillar={pillar}, artifacts={artifact_count}")
        
        if recent_summaries:
            parts.append("\nRecent findings:")
            for summary in recent_summaries:
                parts.append(f"  {summary}")
        
        parts.append(f"\nAnalyst: {user_input}")
        
        context = "\n".join(parts)
        return self._truncate(context)
    
    def _truncate(self, text: str) -> str:
        """Truncate text to max_context_chars."""
        if len(text) <= self.max_context_chars:
            return text
        
        truncated = text[:self.max_context_chars - 50]
        return truncated + "\n\n[Context truncated for token budget]"
