"""Console output that survives a terminal which cannot encode it.

Windows still defaults to a code page — cp1252 on most installs — whenever
output is not a terminal, which is to say whenever anyone pipes, redirects, or
captures it. `✓` has no cp1252 representation, so printing one does not degrade:
it raises `UnicodeEncodeError` and takes the command down. `bastion doctor` and
`bastion explain` both crashed that way, having printed half their output first.

Two defences, because either alone leaves a gap. Glyphs are chosen against what
the stream can actually encode, so ordinary output stays readable rather than
becoming question marks. And the stream is put into replacement mode, so a
character nobody anticipated — from a tool name, an upstream error, a future
edit to this code — degrades to `?` instead of aborting a command mid-write.
"""

from __future__ import annotations

import contextlib
import sys
from dataclasses import dataclass
from typing import IO, Any

from rich.console import Console

FANCY_MARKS = ("✓", "✗", "-")
PLAIN_MARKS = ("OK", "X", "-")


@dataclass(frozen=True)
class Marks:
    """The pass/fail/skipped glyphs a particular stream can render."""

    ok: str
    bad: str
    skip: str

    @property
    def fancy(self) -> bool:
        return self.ok == FANCY_MARKS[0]


def encodable(text: str, stream: IO[str] | None = None) -> bool:
    """Whether ``stream`` can represent ``text`` without raising."""
    encoding = getattr(stream or sys.stdout, "encoding", None)
    if not encoding:
        return True  # no declared encoding (a capture buffer); assume it copes
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def marks_for(stream: IO[str] | None = None) -> Marks:
    """Pick pass/fail glyphs this stream can actually print."""
    return Marks(*(FANCY_MARKS if encodable("".join(FANCY_MARKS), stream) else PLAIN_MARKS))


def harden(stream: Any) -> None:
    """Make ``stream`` replace characters it cannot encode instead of raising.

    A safety net rather than the main defence: it keeps a command from dying
    part-written when something unanticipated reaches the terminal — an upstream
    error message, a tool name, a box-drawing character Rich chose.
    """
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return  # a capture buffer or a stream we do not own
    with contextlib.suppress(ValueError, OSError):  # detached, or not reconfigurable
        reconfigure(errors="replace")


def build(*, stderr: bool = False) -> Console:
    """A Rich console that will not crash on the encoding it was handed."""
    harden(sys.stderr if stderr else sys.stdout)
    return Console(stderr=stderr)
