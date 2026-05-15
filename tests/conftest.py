"""Shared fixtures for the mcpwarden test suite."""

import sys
from pathlib import Path

import pytest

SAMPLE_UPSTREAM = Path(__file__).parent / "fixtures" / "sample_upstream.py"


@pytest.fixture
def sample_upstream() -> Path:
    """Filesystem path to the sample upstream MCP server script."""
    return SAMPLE_UPSTREAM


@pytest.fixture
def python_exe() -> str:
    """Path to the running Python interpreter, used to launch stdio upstreams."""
    return sys.executable
