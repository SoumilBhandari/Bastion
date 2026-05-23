"""Budget tracking — counts and costs over fixed time windows."""

from __future__ import annotations

from bastion.config.schema import CostConfig


class CostModel:
    """Resolves the cost of a tool call from a :class:`CostConfig`.

    Tools listed in ``per_tool`` use their configured cost; everything else
    falls back to ``default_per_call``.
    """

    def __init__(self, config: CostConfig) -> None:
        self._default = config.default_per_call
        self._per_tool = dict(config.per_tool)

    def cost_for(self, tool: str) -> float:
        return self._per_tool.get(tool, self._default)
