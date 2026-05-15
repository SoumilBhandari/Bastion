"""A minimal MCP server used as a test upstream for the Bastion gateway.

Run as a stdio server (default) or over HTTP:

    python sample_upstream.py            # stdio
    python sample_upstream.py http 9123  # HTTP on 127.0.0.1:9123
"""

import sys

from fastmcp import FastMCP

mcp: FastMCP = FastMCP("sample-upstream")


@mcp.tool
def echo(text: str) -> str:
    """Return the given text unchanged."""
    return text


@mcp.tool
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


@mcp.tool
def delete_thing(name: str) -> str:
    """Pretend to delete something and report what was deleted."""
    return f"deleted {name}"


@mcp.tool
def write_note(path: str, body: str) -> str:
    """Pretend to write a note and report how many bytes were written."""
    return f"wrote {len(body)} bytes to {path}"


def main() -> None:
    if len(sys.argv) > 2 and sys.argv[1] == "http":
        mcp.run(transport="http", host="127.0.0.1", port=int(sys.argv[2]), show_banner=False)
    else:
        mcp.run(show_banner=False)


if __name__ == "__main__":
    main()
