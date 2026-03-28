"""
Event Mill Structured Logging

JSON-structured logging for audit, review, and debugging.
Follows the grounding document section 8 requirements.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging.
    
    Produces one JSON object per log line for easy parsing
    by log aggregation tools.
    """
    
    FIELDS = {
        "timestamp",
        "level",
        "logger",
        "message",
        "session_id",
        "tool_name",
        "execution_id",
        "artifact_id",
        "pillar",
        "duration_ms",
        "error",
    }
    
    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as JSON."""
        log_entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add extra fields if present
        for field in self.FIELDS:
            if field not in log_entry and hasattr(record, field):
                value = getattr(record, field)
                if value is not None:
                    log_entry[field] = value
        
        # Add exception info
        if record.exc_info and record.exc_info[1]:
            log_entry["error"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }
        
        return json.dumps(log_entry, default=str)


class ConsoleFormatter(logging.Formatter):
    """Human-readable console formatter with color support."""
    
    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"
    
    def format(self, record: logging.LogRecord) -> str:
        """Format a log record for console display."""
        color = self.COLORS.get(record.levelname, "")
        reset = self.RESET if color else ""
        
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        
        # Build prefix with optional context fields
        prefix_parts = [f"{color}{record.levelname:8s}{reset}", timestamp]
        
        if hasattr(record, "tool_name") and record.tool_name:
            prefix_parts.append(f"[{record.tool_name}]")
        elif record.name.startswith("eventmill."):
            short_name = record.name.replace("eventmill.", "")
            prefix_parts.append(f"[{short_name}]")
        
        prefix = " ".join(prefix_parts)
        return f"{prefix} {record.getMessage()}"


def setup_logging(
    log_level: str = "INFO",
    log_file: str | Path | None = None,
    console: bool = True,
    json_format: bool = True,
) -> logging.Logger:
    """Configure Event Mill logging.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR).
        log_file: Path to log file (None for no file logging).
        console: Whether to log to console.
        json_format: Whether to use JSON format for file logging.
    
    Returns:
        Root Event Mill logger.
    """
    root_logger = logging.getLogger("eventmill")
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(ConsoleFormatter())
        root_logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(str(log_path))
        
        if json_format:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)s %(name)s %(message)s"
                )
            )
        
        root_logger.addHandler(file_handler)
    
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a named Event Mill logger.
    
    Args:
        name: Logger name (will be prefixed with 'eventmill.').
    
    Returns:
        Logger instance.
    """
    if not name.startswith("eventmill."):
        name = f"eventmill.{name}"
    return logging.getLogger(name)


class LogContext:
    """Context manager for adding structured fields to log records.
    
    Usage:
        with LogContext(session_id="sess_abc", tool_name="threat_intel_ingester"):
            logger.info("Processing artifact")
            # Log record will include session_id and tool_name
    """
    
    def __init__(self, **kwargs: Any):
        """Initialize with extra log fields.
        
        Args:
            **kwargs: Extra fields to add to log records.
        """
        self.extra = kwargs
        self._old_factory = None
    
    def __enter__(self) -> LogContext:
        self._old_factory = logging.getLogRecordFactory()
        extra = self.extra
        old_factory = self._old_factory
        
        def record_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
            record = old_factory(*args, **kwargs)
            for key, value in extra.items():
                setattr(record, key, value)
            return record
        
        logging.setLogRecordFactory(record_factory)
        return self
    
    def __exit__(self, *args: Any) -> None:
        if self._old_factory:
            logging.setLogRecordFactory(self._old_factory)
