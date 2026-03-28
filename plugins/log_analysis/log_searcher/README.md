# Log Searcher

**Search log files for text or regex patterns with context lines.**

## What It Does

Searches log files for matching lines using case-insensitive text or regex patterns. Returns matching lines with line numbers and optional surrounding context. Supports invert mode for exclusion filtering.

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `text`, `log_stream` | Log files to search |
| Produced | `json_events` | Structured search results |

## Example Usage

### Simple Text Search
```json
{"file_path": "/workspace/artifacts/app.log", "query": "ERROR", "max_results": 50}
```

### Regex Search with Context
```json
{"file_path": "/workspace/artifacts/app.log", "query": "ERROR.*(timeout|refused)", "mode": "regex", "context_lines": 2}
```

### Invert (Exclusion) Search
```json
{"file_path": "/workspace/artifacts/app.log", "query": "INFO", "invert": true}
```

## Chains

- **From**: `log_navigator`, `log_pattern_analyzer`
- **To**: `log_pattern_analyzer`, `log_investigator`
