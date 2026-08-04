"""Bounds on how much work one call can make Bastion do.

Arguments come from the agent and results come from upstreams, so both are
shaped by something other than the operator. Every walk over them needs a
limit, or a single pathological value decides how long the gateway spends and
how deep it recurses.
"""

from __future__ import annotations

MAX_STRUCTURE_DEPTH = 100
"""How far into a nested value Bastion will walk.

A result nested a few thousand levels deep — which an upstream can simply
return — exhausted the interpreter stack in every recursive walk: redaction,
serialisation, and the flattening that feeds the scanners. Real arguments and
results are nowhere near this deep.

Past the limit the subtree is replaced by :data:`TOO_DEEP` rather than left
alone, so nothing slips through a walk that was supposed to inspect it.
"""

TOO_DEEP = "<truncated: nested too deeply for Bastion to inspect>"
"""Stands in for a subtree past :data:`MAX_STRUCTURE_DEPTH`.

Deliberately conspicuous: if this ever appears in an audit log or a result, the
value was not examined, and reading it as ordinary data would be wrong.
"""
