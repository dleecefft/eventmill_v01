"""
Asset Inventory Lookup — Event Mill Plugin

Queries a BigQuery asset inventory table to correlate IP addresses
from threat intel IOC extractions against known internal assets.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from framework.plugins.protocol import ToolResult, ValidationResult, QueryHints

logger = logging.getLogger("eventmill.plugin.asset_inventory_lookup")


class AssetInventoryLookup:
    """Look up IPs from threat intel artifacts against a BigQuery asset inventory."""

    def __init__(self):
        self._manifest = None

    # ------------------------------------------------------------------
    # Manifest
    # ------------------------------------------------------------------

    def _load_manifest(self) -> dict:
        if self._manifest is None:
            manifest_path = Path(__file__).parent / "manifest.json"
            with open(manifest_path, "r", encoding="utf-8") as f:
                self._manifest = json.load(f)
        return self._manifest

    # ------------------------------------------------------------------
    # Protocol Methods
    # ------------------------------------------------------------------

    def metadata(self) -> dict:
        m = self._load_manifest()
        return {
            "tool_name": m["tool_name"],
            "version": m["version"],
            "pillar": m["pillar"],
            "display_name": m["display_name"],
            "description_short": m["description_short"],
            "description_llm": m["description_llm"],
            "artifacts_consumed": m["artifacts_consumed"],
            "artifacts_produced": m["artifacts_produced"],
            "capabilities": m["capabilities"],
        }

    def validate_inputs(self, payload: dict) -> ValidationResult:
        errors: list[str] = []

        artifact_id = payload.get("artifact_id")
        if not artifact_id:
            errors.append("artifact_id is required")

        bq_table = payload.get("bq_table") or payload.get("config", {}).get("bq_table")
        if not bq_table:
            errors.append(
                "bq_table is required (provide via payload or config). "
                "Format: project.dataset.table"
            )

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(self, payload: dict, context: Any) -> ToolResult:
        # ----------------------------------------------------------
        # 1. Resolve the source artifact (json_events from threat_intel_ingester)
        # ----------------------------------------------------------
        artifact_id = payload.get("artifact_id")
        artifact = None
        for art in getattr(context, "artifacts", []):
            if art.artifact_id == artifact_id:
                artifact = art
                break

        if artifact is None:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=f"Artifact {artifact_id} not found in session",
            )

        # Load the JSON artifact
        try:
            with open(artifact.file_path, "r", encoding="utf-8") as f:
                ioc_data = json.load(f)
        except Exception as exc:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_READ_ERROR",
                message=f"Failed to read artifact: {exc}",
            )

        # ----------------------------------------------------------
        # 2. Extract IP addresses from the IOC data
        # ----------------------------------------------------------
        ips = set()
        iocs = ioc_data.get("iocs", ioc_data.get("indicators", []))
        if isinstance(iocs, list):
            for ioc in iocs:
                if isinstance(ioc, dict):
                    if ioc.get("ioc_type") == "ip" or ioc.get("type") == "ip":
                        val = ioc.get("value", "")
                        if val:
                            ips.add(val)
                elif isinstance(ioc, str):
                    ips.add(ioc)

        # Also check for a flat ip list
        ip_list = ioc_data.get("ips", [])
        if isinstance(ip_list, list):
            ips.update(str(ip) for ip in ip_list if ip)

        if not ips:
            return ToolResult(
                ok=True,
                result={
                    "total_ips_queried": 0,
                    "matched_assets": [],
                    "unmatched_ips": [],
                    "asset_types": {},
                    "message": "No IP addresses found in source artifact",
                },
            )

        # ----------------------------------------------------------
        # 3. Query BigQuery asset inventory
        # ----------------------------------------------------------
        config = getattr(context, "config", {}) or {}
        bq_table = payload.get("bq_table") or config.get("bq_table", "")

        try:
            from google.cloud import bigquery

            client = bigquery.Client()
            ip_list_str = ", ".join(f"'{ip}'" for ip in sorted(ips))
            query = (
                f"SELECT * FROM `{bq_table}` "
                f"WHERE ip_address IN ({ip_list_str})"
            )
            logger.info("Querying BigQuery: %s", bq_table)
            query_job = client.query(query)
            rows = [dict(row) for row in query_job]
        except ImportError:
            return ToolResult(
                ok=False,
                error_code="DEPENDENCY_MISSING",
                message="google-cloud-bigquery is required. Install with: pip install google-cloud-bigquery",
            )
        except Exception as exc:
            return ToolResult(
                ok=False,
                error_code="BIGQUERY_ERROR",
                message=f"BigQuery query failed: {exc}",
            )

        # ----------------------------------------------------------
        # 4. Build results
        # ----------------------------------------------------------
        matched_ips = {row.get("ip_address") for row in rows if row.get("ip_address")}
        unmatched = sorted(ips - matched_ips)

        # Tally asset types
        asset_types: dict[str, int] = {}
        for row in rows:
            atype = row.get("asset_type", "unknown")
            asset_types[atype] = asset_types.get(atype, 0) + 1

        result_data = {
            "total_ips_queried": len(ips),
            "matched_assets": rows,
            "unmatched_ips": unmatched,
            "asset_types": asset_types,
        }

        # ----------------------------------------------------------
        # 5. Register output artifact
        # ----------------------------------------------------------
        if hasattr(context, "register_artifact"):
            import tempfile, os

            out_path = os.path.join(
                tempfile.gettempdir(),
                f"asset_lookup_{artifact_id}.json",
            )
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result_data, f, indent=2, default=str)

            ref = context.register_artifact(
                artifact_type="json_events",
                file_path=out_path,
                source_tool="asset_inventory_lookup",
                metadata={
                    "total_ips": len(ips),
                    "matched": len(rows),
                    "unmatched": len(unmatched),
                },
            )
            output_artifacts = [
                {
                    "artifact_id": ref.artifact_id,
                    "artifact_type": "json_events",
                    "description": "Asset inventory lookup results",
                }
            ]
        else:
            output_artifacts = []

        return ToolResult(
            ok=True,
            result=result_data,
            output_artifacts=output_artifacts,
        )

    def summarize_for_llm(self, result: Any) -> str:
        if not result or not result.ok or not result.result:
            return "Asset inventory lookup produced no results."

        r = result.result
        total = r.get("total_ips_queried", 0)
        matched = len(r.get("matched_assets", []))
        unmatched = r.get("unmatched_ips", [])
        asset_types = r.get("asset_types", {})

        lines = [
            f"Asset Inventory Lookup: {total} IPs queried, {matched} matched, {len(unmatched)} unmatched.",
        ]
        if asset_types:
            type_str = ", ".join(f"{k}: {v}" for k, v in asset_types.items())
            lines.append(f"Asset types: {type_str}")
        if unmatched:
            lines.append(f"Unmatched IPs: {', '.join(unmatched[:20])}")

        return "\n".join(lines)
