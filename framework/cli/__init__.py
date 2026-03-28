"""
Event Mill CLI Interface

Metasploit-style command shell with tab completion, help screens,
and user input handling.
"""

from .shell import EventMillShell, main

__all__ = [
    "EventMillShell",
    "main",
]
