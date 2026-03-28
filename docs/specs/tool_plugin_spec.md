# Event Mill Tool Plugin Specification

Version: 0.2.0
Aligned with: eventmill_v1_1.md (v0.2.0-draft)

---

## Purpose

This document defines the minimum contract for Event Mill plugins. It is the **normative** specification for plugin development. Where this document and other design documents conflict, this document wins for plugin behavior.

The goals are:

- consistent tool behavior across all five investigation pillars
- deterministic plugin discovery and routing
- reduced LLM context consumption through compressed summaries
- CI-validatable plugin packages before acceptance
- support for local, verified, experimental, and deprecated plugins without framework code changes

This specification borrows proven extension patterns from Metasploit modules, Terraform providers, and editor extension ecosystems. A plugin is self-describing, schema-driven, and executable through a stable runtime contract.

---

## Normative Language

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are interpreted per RFC 2119.

---

## Plugin Packaging Requirements

Every plugin MUST live in its own directory and MUST include:

```text
<plugin_name>/
├── manifest.json
├── tool.py
├── README.md
├── schemas/
│   ├── input.schema.json
│   └── output.schema.json
├── examples/
│   ├── request.example.json
│   └── response.example.json
├── tests/
│   └── test_contract.py
└── data/                          # OPTIONAL — plugin-specific reference data
    └── <reference_files>
```

A plugin MAY include additional implementation files, helper modules, fixtures, or static assets.

The optional `data/` directory contains plugin-specific reference data that extends or overrides the framework's common reference data when this plugin is active. If present, the plugin manifest MUST document any overrides in the `reference_data_overrides` field, and the README MUST explain what is overridden and why.

---

## Directory Placement

Plugins are grouped by pillar:

```text
plugins/
├── network_forensics/
│   ├── pcap_metadata_summary/
│   ├── pcap_ip_search/
│   ├── pcap_flow_analyzer/
│   └── firewall_log_aggregator/
├── cloud_investigation/
├── log_analysis/
│   ├── event_source_profiler/
│   ├── pattern_extractor/
│   ├── threat_intel_ingester/
│   ├── context_enriched_analyzer/
│   └── image_analyzer/
├── risk_assessment/
└── threat_modeling/
    ├── threat_model_builder/
    ├── attack_path_generator/
    └── attack_path_renderer/
```

The pillar folder is an organizational and routing boundary. A plugin MUST declare the same pillar in `manifest.json` as the directory it is stored under.

---

## Plugin Identity and Naming

Each plugin MUST have a stable `tool_name`.

Rules:

- lowercase letters, digits, and underscores only
- SHOULD begin with a short domain prefix when useful: `pcap_`, `azure_`, `gcp_`, `risk_`, `ti_`, `tm_`
- MUST be unique across the loaded registry
- SHOULD remain stable across backward-compatible releases

---

## Manifest Requirements

Each plugin MUST provide a valid `manifest.json` conforming to `manifest_schema.json`.

Key changes from 0.1.0:

- `artifacts_supported` is replaced by `artifacts_consumed` and `artifacts_produced` to support tool chaining
- `requires_llm` is a new field for tools that depend on LLM capabilities
- `reference_data_overrides` declares which framework reference data entries the plugin extends
- `chains_to` is an advisory field for the router describing downstream tool compatibility

See `manifest_schema.json` for the complete field reference.

---

## Capability Declaration

Capabilities drive routing and tool filtering.

A plugin MUST declare capabilities using concise namespace-style strings.

Recommended namespaces:

| Namespace | Purpose | Examples |
|-----------|---------|----------|
| `artifact` | Input/output types | `artifact:pcap`, `artifact:pdf_report` |
| `operation` | What the tool does | `operation:search`, `operation:parse`, `operation:enrich`, `operation:summarize` |
| `entity` | Objects the tool reasons about | `entity:ip`, `entity:dns`, `entity:ioc`, `entity:mitre_technique` |
| `domain` | Subject area | `domain:network_forensics`, `domain:threat_intel` |
| `output` | Output format | `output:table`, `output:mermaid`, `output:json` |

Rules:

- capabilities MUST be strings matching `^[a-z]+:[A-Za-z0-9_.-]+$`
- capabilities SHOULD be stable and reusable across plugins
- capabilities SHOULD be broad enough to enable routing but specific enough to differentiate tools
- capabilities MUST NOT encode implementation details

---

## Artifact Support

Plugins declare artifact relationships with two fields:

- `artifacts_consumed` — input types the tool accepts
- `artifacts_produced` — output types the tool generates

Supported artifact types:

| Type | Description |
|------|-------------|
| `pcap` | Network packet capture files |
| `json_events` | Structured event records in JSON |
| `log_stream` | Semi-structured or unstructured log data |
| `risk_model` | Risk assessment or threat model output |
| `cloud_audit_log` | Cloud provider audit trail exports |
| `pdf_report` | PDF-formatted threat intel reports, vendor advisories |
| `html_report` | HTML-formatted blog posts, advisories, CERT bulletins |
| `image` | JPG/PNG images for physical intrusion or visual analysis |
| `text` | Plain text, CSVs, generic structured text |
| `none` | Tools requiring no input artifact (e.g., interactive threat model builder) |

Use `none` in `artifacts_consumed` only for tools that generate output from user interaction alone.

Use `none` in `artifacts_produced` only for tools whose output is purely informational text displayed inline (no registered artifact).

---

## Stability Classes

Each plugin MUST declare a `stability` level:

| Level | Meaning | Default visibility |
|-------|---------|-------------------|
| `experimental` | Local testing, not enabled by default | Hidden unless opted in |
| `verified` | Contract tests pass, code reviewed | Visible, not auto-invokable |
| `core` | Maintained by the project team | Visible, follows `safe_for_auto_invoke` |
| `deprecated` | Loadable but scheduled for removal | Hidden unless opted in |

---

## Runtime Interface

The runtime contract is Python-based. The tool module MUST expose a class whose name matches `class_name` in the manifest. That class MUST implement `EventMillToolProtocol`:

```python
from typing import Protocol, Any
from dataclasses import dataclass


@dataclass
class ToolResult:
    """Standard tool execution result."""
    ok: bool
    result: dict[str, Any] | None = None
    error_code: str | None = None
    message: str | None = None
    details: dict[str, Any] | None = None
    output_artifacts: list[dict[str, Any]] | None = None


@dataclass
class ValidationResult:
    """Input validation result."""
    ok: bool
    errors: list[str] | None = None


class EventMillToolProtocol(Protocol):

    def metadata(self) -> dict:
        """Return runtime metadata. Reflects manifest plus derived runtime values.
        Used for diagnostics, registry inspection, and debugging."""
        ...

    def validate_inputs(self, payload: dict) -> ValidationResult:
        """Validate the request payload against the input schema.
        MUST NOT perform any analysis work or side effects."""
        ...

    def execute(self, payload: dict, context: 'ExecutionContext') -> ToolResult:
        """Perform the tool's analysis work and return a structured result.
        
        Rules:
        - MUST NOT mutate framework state directly
        - MUST NOT call other plugins directly
        - MUST treat context as read-only
        - SHOULD prefer deterministic logic
        - MUST raise predictable exceptions or return structured errors
        - MUST register output artifacts via context.register_artifact()
        """
        ...

    def summarize_for_llm(self, result: ToolResult) -> str:
        """Return a compressed, human-readable summary for the LLM context window.
        
        Rules:
        - MUST be brief (target: under 500 tokens)
        - SHOULD include only the most important findings
        - MUST NOT repeat the full structured output
        - MUST NOT invent facts not present in result
        - MUST NOT include binary data references
        
        This method is a critical differentiator for Event Mill.
        Most MCP-based projects skip explicit output compression,
        leading to context window bloat and degraded LLM reasoning.
        """
        ...
```

---

## Execution Context Contract

The framework supplies an `ExecutionContext` object to `execute()`. This replaces the raw `context: dict` from v0.1.0.

```python
@dataclass
class ExecutionContext:
    """Read-only execution context supplied by the framework."""
    
    # Session identity
    session_id: str
    selected_pillar: str
    
    # Artifact access
    artifacts: list[ArtifactRef]        # Registered artifacts in this session
    
    # Framework services (read-only interfaces)
    config: dict                         # Framework and plugin configuration
    logger: logging.Logger               # Namespaced logger: eventmill.plugin.<tool_name>
    reference_data: ReferenceDataView    # Common + plugin-specific reference data
    
    # Capabilities
    llm_enabled: bool                    # True if MCP connection is live
    llm_query: LLMQueryInterface | None  # None if llm_enabled is False
    
    # Artifact registration (the one write operation plugins may perform)
    register_artifact: Callable[[str, str, str, dict], ArtifactRef]
    
    # Execution limits
    limits: dict                         # timeout, max_output_size, etc.


@dataclass
class ArtifactRef:
    """Reference to a registered artifact. Immutable after creation."""
    artifact_id: str
    artifact_type: str                   # From the artifact type enum
    file_path: str                       # Resolved path on the storage backend
    source_tool: str | None              # None for user-provided artifacts
    metadata: dict
```

Plugins MUST treat missing optional attributes gracefully. Plugins MUST NOT assume any undocumented attributes exist.

---

## LLM Query Interface

Plugins that require LLM capabilities (manifest `requires_llm: true`) use the `LLMQueryInterface` from the execution context:

```python
class LLMQueryInterface(Protocol):

    def query_text(
        self,
        prompt: str,
        system_context: str | None = None,
        max_tokens: int = 4096,
        grounding_data: list[str] | None = None
    ) -> LLMResponse:
        """Send a text prompt to the connected LLM via MCP.
        
        grounding_data: Additional context strings injected before the prompt.
        These are typically reference data entries or compressed prior results.
        """
        ...

    def query_multimodal(
        self,
        prompt: str,
        image_data: bytes,
        image_format: str,
        system_context: str | None = None,
        max_tokens: int = 4096
    ) -> LLMResponse:
        """Send a multimodal (text + image) prompt to the connected LLM.
        
        If the connected model does not support vision, MUST return
        an LLMResponse with ok=False and error indicating capability gap.
        """
        ...


@dataclass
class LLMResponse:
    ok: bool
    text: str | None = None
    error: str | None = None
    token_usage: dict | None = None
```

The framework owns the MCP client. Plugins MUST NOT create their own MCP connections. All LLM interaction goes through the context interface, which allows the framework to:

- enforce rate limiting and cost tracking
- inject system context and reference data grounding
- log LLM interactions at DEBUG level per the logging spec
- handle timeouts and retries at the transport level

---

## Input and Output Schemas

A plugin MUST provide both `schemas/input.schema.json` and `schemas/output.schema.json`.

Rules:

- MUST use JSON Schema draft 2020-12 with `$schema` set
- MUST include descriptions for all required fields
- SHOULD model errors separately from success results
- SHOULD avoid unbounded free-form objects unless justified
- Output schema MUST support the `ToolResult` envelope: `{ok, result, error_code, message, details, output_artifacts}`

---

## Error Handling

Plugins SHOULD return structured failure data via the `ToolResult` envelope:

```json
{
  "ok": false,
  "error_code": "INPUT_VALIDATION_FAILED",
  "message": "ip_address is required",
  "details": {}
}
```

Recommended error codes:

| Code | Meaning |
|------|---------|
| `INPUT_VALIDATION_FAILED` | Payload does not conform to input schema |
| `ARTIFACT_NOT_FOUND` | Referenced artifact does not exist |
| `ARTIFACT_UNREADABLE` | Artifact file exists but cannot be parsed |
| `LLM_UNAVAILABLE` | requires_llm=true but MCP connection is down |
| `LLM_CAPABILITY_GAP` | Connected model lacks required capability (e.g., vision) |
| `LLM_QUERY_FAILED` | LLM returned an error or unparseable response |
| `TIMEOUT` | Execution exceeded the timeout_class limit |
| `DEPENDENCY_MISSING` | Required Python package not available |
| `INTERNAL_ERROR` | Unexpected failure — include details for debugging |

---

## Timeouts and Cost Hints

Each plugin MUST declare `timeout_class`:

| Class | Default limit | Use case |
|-------|--------------|----------|
| `fast` | 30 seconds | Interactive, single-file parsing |
| `medium` | 120 seconds | Multi-step analysis, moderate I/O |
| `slow` | 600 seconds | LLM-intensive, large artifact processing |

A plugin MAY declare `cost_hint` (`low`, `moderate`, `high`) for future scheduling and UI display.

---

## Auto-Invocation Safety

Each plugin MUST declare `safe_for_auto_invoke`:

- `true` — read-only, low-risk, low-cost tools the LLM may invoke without analyst confirmation
- `false` — tools with external side effects, high cost, or results that require analyst judgment before acting on

---

## Tests

Each plugin MUST include at least one contract test (`tests/test_contract.py`) that verifies:

1. manifest.json loads and validates against manifest_schema.json
2. input schema and output schema load and are valid JSON Schema
3. entry_point module imports without errors
4. tool class can be instantiated
5. `validate_inputs()` correctly accepts the example request
6. `validate_inputs()` correctly rejects a deliberately malformed request
7. example request validates against input schema
8. example response validates against output schema
9. `summarize_for_llm()` returns a non-empty string under 2000 characters when given the example response
10. `metadata()` returns a dict containing at minimum `tool_name` and `version`

---

## README Requirements

Each plugin README MUST include:

- Purpose and use cases
- Supported artifact types (consumed and produced)
- LLM dependency status (requires_llm)
- Example request and response
- Example `summarize_for_llm()` output
- Limitations and known gaps
- Safety notes (auto-invoke considerations)
- Dependency notes (packages beyond framework baseline)
- Reference data overrides (if any)

---

## Versioning

Plugin `version` MUST use semantic versioning:

- Patch: non-breaking fixes
- Minor: backward-compatible enhancements (new optional output fields)
- Major: breaking contract changes (input schema changes, output schema restructuring)

---

## Backward Compatibility

A plugin SHOULD preserve its input/output contract within a major version. On breaking changes:

- increment major version
- update schemas, examples, tests, and README
- add a migration note to the README

---

## Acceptance Checklist

A plugin is ready for registration when:

- [ ] Directory structure is complete per packaging requirements
- [ ] `manifest.json` validates against `manifest_schema.json`
- [ ] `pillar` in manifest matches the plugin's directory placement
- [ ] Input and output schemas are valid JSON Schema draft 2020-12
- [ ] Example request validates against input schema
- [ ] Example response validates against output schema
- [ ] Contract tests pass (`pytest tests/test_contract.py`)
- [ ] `summarize_for_llm()` produces output under 2000 characters
- [ ] README exists and covers all required sections
- [ ] Capabilities are reasonable and reusable
- [ ] `requires_llm` is set correctly
- [ ] `artifacts_consumed` and `artifacts_produced` accurately reflect tool behavior
- [ ] Reference data overrides (if any) are documented in manifest and README
