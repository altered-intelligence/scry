"""Shared error type for AI-facing service functions.

AskError carries an HTTP-style status code + user-facing message so the REST
layer (maps it to HTTPException) and the MCP server (maps it to an error
dict) can share one implementation without web exceptions leaking into
non-HTTP surfaces.
"""

from __future__ import annotations


class AskError(Exception):
    """An AI request could not be fulfilled — carries status + message."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)
