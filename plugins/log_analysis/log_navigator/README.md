# Log Navigator

**List, read, and inspect log files from local or cloud storage.**

## What It Does

Entry point for the analyst workflow. Three actions:

1. **list** — List files and subdirectories at a path, sorted with directories first
2. **read** — Read paginated segments of a log file with offset/limit
3. **metadata** — Get file size, modification time, and line count

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | — | — |
| Produced | `text`, `log_stream` | Log files for downstream tools |

## Example Usage

### List Directory
```json
{"action": "list", "path": "/workspace/artifacts", "prefix": "access", "max_results": 50}
```

### Read Segment (Pagination)
```json
{"action": "read", "path": "/workspace/artifacts/access.log", "offset_lines": 0, "line_limit": 100}
```

### Get Metadata
```json
{"action": "metadata", "path": "/workspace/artifacts/access.log"}
```

## Chains

- **To**: `log_pattern_analyzer`, `log_searcher`, `log_investigator`
