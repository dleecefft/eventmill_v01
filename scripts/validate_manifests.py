#!/usr/bin/env python3
"""
Validate all plugin manifests against manifest_schema.json.

Usage:
    python scripts/validate_manifests.py

Exit codes:
    0 - All manifests valid
    1 - One or more manifests invalid
"""

import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print("ERROR: jsonschema package required. Install with: pip install jsonschema")
    sys.exit(1)


def main():
    root = Path(__file__).parent.parent
    schema_path = root / "docs" / "specs" / "manifest_schema.json"
    plugins_dir = root / "plugins"

    if not schema_path.exists():
        print(f"ERROR: Schema not found at {schema_path}")
        sys.exit(1)

    with open(schema_path) as f:
        schema = json.load(f)

    errors = []
    validated = 0

    for pillar_dir in plugins_dir.iterdir():
        if not pillar_dir.is_dir() or pillar_dir.name.startswith("_"):
            continue

        for plugin_dir in pillar_dir.iterdir():
            if not plugin_dir.is_dir() or plugin_dir.name.startswith("_"):
                continue

            manifest_path = plugin_dir / "manifest.json"
            if not manifest_path.exists():
                errors.append(f"{plugin_dir.name}: manifest.json not found")
                continue

            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)

                jsonschema.validate(manifest, schema)

                # Check pillar matches directory
                if manifest.get("pillar") != pillar_dir.name:
                    errors.append(
                        f"{plugin_dir.name}: pillar '{manifest.get('pillar')}' "
                        f"does not match directory '{pillar_dir.name}'"
                    )
                else:
                    validated += 1
                    print(f"✓ {pillar_dir.name}/{plugin_dir.name}")

            except json.JSONDecodeError as e:
                errors.append(f"{plugin_dir.name}: Invalid JSON - {e}")
            except jsonschema.ValidationError as e:
                errors.append(f"{plugin_dir.name}: Schema validation failed - {e.message}")

    print()
    print(f"Validated: {validated} plugins")

    if errors:
        print(f"Errors: {len(errors)}")
        for error in errors:
            print(f"  ✗ {error}")
        sys.exit(1)

    print("All manifests valid.")
    sys.exit(0)


if __name__ == "__main__":
    main()
