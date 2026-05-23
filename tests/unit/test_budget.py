"""Unit tests for budget tracking."""

from __future__ import annotations

from bastion.config.schema import CostConfig
from bastion.policy.budget import CostModel


def test_cost_falls_back_to_default() -> None:
    model = CostModel(CostConfig(default_per_call=0.01))
    assert model.cost_for("anything") == 0.01


def test_cost_uses_per_tool_override() -> None:
    model = CostModel(CostConfig(default_per_call=0.01, per_tool={"search_web": 0.10}))
    assert model.cost_for("search_web") == 0.10
    assert model.cost_for("echo") == 0.01


def test_cost_is_zero_when_unset() -> None:
    model = CostModel(CostConfig())
    assert model.cost_for("anything") == 0.0
