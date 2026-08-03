"""Unit tests for console output that has to survive its terminal."""

import io
import sys

from bastion.console import FANCY_MARKS, PLAIN_MARKS, build, encodable, harden, marks_for


class _Stream(io.StringIO):
    """A text stream that declares an encoding, the way a real one does."""

    def __init__(self, encoding: str) -> None:
        super().__init__()
        self._encoding = encoding
        self.reconfigured: dict[str, object] = {}

    @property
    def encoding(self) -> str:
        return self._encoding

    def reconfigure(self, **kwargs: object) -> None:
        self.reconfigured.update(kwargs)


def test_utf8_can_encode_the_fancy_marks() -> None:
    assert encodable("✓✗", _Stream("utf-8"))


def test_cp1252_cannot_encode_the_fancy_marks() -> None:
    """Windows uses this code page whenever output is not a terminal."""
    assert not encodable("✓✗", _Stream("cp1252"))


def test_cp1252_can_encode_an_em_dash() -> None:
    """Not everything non-ASCII is a problem; only degrade what has to be."""
    assert encodable("—", _Stream("cp1252"))


def test_an_unknown_encoding_is_not_treated_as_capable() -> None:
    assert not encodable("✓", _Stream("definitely-not-a-codec"))


def test_a_stream_without_an_encoding_is_assumed_capable() -> None:
    """A capture buffer has no encoding; it is not a reason to degrade output."""
    assert encodable("✓", io.StringIO())


def test_marks_are_fancy_on_a_capable_stream() -> None:
    marks = marks_for(_Stream("utf-8"))
    assert (marks.ok, marks.bad, marks.skip) == FANCY_MARKS
    assert marks.fancy


def test_marks_fall_back_on_an_incapable_stream() -> None:
    marks = marks_for(_Stream("cp1252"))
    assert (marks.ok, marks.bad, marks.skip) == PLAIN_MARKS
    assert not marks.fancy


def test_fallback_marks_are_pure_ascii() -> None:
    assert all(mark.isascii() for mark in PLAIN_MARKS)


def test_hardening_puts_a_stream_into_replacement_mode() -> None:
    stream = _Stream("cp1252")
    harden(stream)
    assert stream.reconfigured == {"errors": "replace"}


def test_hardening_ignores_a_stream_it_cannot_reconfigure() -> None:
    harden(io.StringIO())  # no reconfigure attribute; must not raise


def test_hardening_survives_a_stream_that_refuses() -> None:
    class Refuses(_Stream):
        def reconfigure(self, **kwargs: object) -> None:
            raise ValueError("detached")

    harden(Refuses("cp1252"))  # must not raise


def test_build_returns_a_usable_console() -> None:
    assert build().file is sys.stdout
    assert build(stderr=True).file is sys.stderr
