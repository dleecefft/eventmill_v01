#!/usr/bin/env python3
"""
Generate a human-readable tool catalog from plugin manifests.

Usage:
    python scripts/generate_tool_catalog.py [--format md|json]

Output:
    Prints tool catalog to stdout.
"""

import argparse
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Generate tool catalog")
    parser.add_argument("--format", choices=["md", "json"], default="md")
    args = parser.parse_args()

    root = Path(__file__).parent.parent
    plugins_dir = root / "plugins"

    catalog = {}

    for pillar_dir in sorted(plugins_dir.iterdir()):
        if not pillar_dir.is_dir() or pillar_dir.name.startswith("_"):
            continue

        pillar_name = pillar_dir.name
        catalog[pillar_name] = []

        for plugin_dir in sorted(pillar_dir.iterdir()):
            if not plugin_dir.is_dir() or plugin_dir.name.startswith("_"):
                continue

            manifest_path = plugin_dir / "manifest.json"
            if not manifest_path.exists():
                continue

            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)

                catalog[pillar_name].append({
                    "tool_name": manifest.get("tool_name", plugin_dir.name),
                    "display_name": manifest.get("display_name", ""),
                    "description_short": manifest.get("description_short", ""),
                    "version": manifest.get("version", ""),
                    "stability": manifest.get("stability", ""),
                    "requires_llm": manifest.get("requires_llm", False),
                    "artifacts_consumed": manifest.get("artifacts_consumed", []),
                    "artifacts_produced": manifest.get("artifacts_produced", []),
                })
            except (json.JSONDecodeError, KeyError):
                continue

    if args.format == "json":
        print(json.dumps(catalog, indent=2))
    else:
        print("# Event Mill Tool Catalog\n")
        for pillar, tools in catalog.items():
            print(f"## {pillar.replace('_', ' ').title()}\n")
            if not tools:
                print("*No tools registered*\n")
                continue

            for tool in tools:
                print(f"### {tool['display_name']} (`{tool['tool_name']}`)\n")
                print(f"**Version:** {tool['version']} | **Stability:** {tool['stability']}")
                if tool['requires_llm']:
                    print(" | **Requires LLM**")
                print()
                print(f"{tool['description_short']}\n")
                print(f"- **Consumes:** {', '.join(tool['artifacts_consumed'])}")
                print(f"- **Produces:** {', '.join(tool['artifacts_produced'])}")
                print()


if __name__ == "__main__":
    main()
