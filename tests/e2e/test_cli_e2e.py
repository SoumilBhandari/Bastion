"""End-to-end CLI tests that run `bastion` as a real subprocess.

Typer's CliRunner replaces stdin/stdout with objects that have no ``fileno()``,
which a real stdio MCP transport needs — so anything that actually connects to
an upstream has to be exercised out of process.
"""

import subprocess
import sys
from pathlib import Path

import pytest


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "bastion", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=120,
    )


@pytest.fixture
def project(tmp_path: Path, sample_upstream: Path, python_exe: str) -> Path:
    (tmp_path / "bastion.yaml").write_text(
        f"upstreams:\n  sample:\n    command: {python_exe}\n    args: ['{sample_upstream}']\n"
        "audit:\n  enabled: true\n  path: ./audit.jsonl\n"
        "policy:\n"
        "  default: deny\n"
        "  permissions:\n    - { tool: echo, action: allow }\n"
        "  rate_limits:\n    - { name: cap, scope: global, max_per_minute: 60 }\n",
        encoding="utf-8",
    )
    return tmp_path


def test_doctor_connects_to_a_real_upstream(project: Path) -> None:
    result = _run("doctor", cwd=project)

    assert result.returncode == 0, result.stderr
    assert "8 tools" in result.stdout
    assert "nothing to flag" in result.stdout


def test_pin_approves_then_verifies_clean(project: Path) -> None:
    approved = _run("pin", "--approve", cwd=project)
    assert approved.returncode == 0, approved.stderr
    assert (project / "bastion-pins.json").is_file()

    checked = _run("pin", cwd=project)
    assert checked.returncode == 0, checked.stderr
    assert "match their pins" in checked.stdout


def test_pin_detects_a_changed_definition(
    tmp_path: Path, mutating_upstream: Path, python_exe: str
) -> None:
    config = tmp_path / "bastion.yaml"
    config.write_text(
        f"upstreams:\n  shop:\n    command: {python_exe}\n    args: ['{mutating_upstream}']\n"
        '    env:\n      BASTION_TEST_POISONED: "${POISONED:-0}"\n'
        "audit:\n  enabled: false\n",
        encoding="utf-8",
    )
    assert _run("pin", "--approve", cwd=tmp_path).returncode == 0

    import os

    poisoned = subprocess.run(
        [sys.executable, "-m", "bastion", "pin"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={**os.environ, "POISONED": "1"},
        timeout=120,
    )
    assert poisoned.returncode == 1
    assert "description changed" in poisoned.stdout
    assert "id_rsa" in poisoned.stdout


def test_validate_reports_a_good_config(project: Path) -> None:
    result = _run("validate", cwd=project)
    assert result.returncode == 0
    assert "OK" in result.stdout


def test_explain_runs_against_a_real_config(project: Path) -> None:
    result = _run("explain", "echo", cwd=project)
    assert result.returncode == 0
    assert "ALLOWED" in result.stdout
