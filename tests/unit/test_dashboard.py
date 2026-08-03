"""Unit tests for the audit-log web dashboard."""

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from bastion.audit import AuditRecord, AuditWriter
from bastion.config.schema import BastionConfig
from bastion.dashboard.app import VERIFY_INTERVAL_SECONDS, _summarize, build_dashboard_app

TOKEN = "test-token"


def _record(tool: str, outcome: str = "ok", duration_ms: float = 1.0, **extra: Any) -> str:
    payload: dict[str, Any] = {
        "call_id": "abc",
        "timestamp": "2026-05-16T12:00:00+00:00",
        "tool": tool,
        "arguments": {"x": 1},
        "outcome": outcome,
        "duration_ms": duration_ms,
        "error": None,
    }
    payload.update(extra)
    return json.dumps(payload)


def _config(audit_path: Path) -> BastionConfig:
    return BastionConfig.model_validate(
        {
            "upstreams": {"a": {"command": "x"}},
            "audit": {"enabled": True, "path": str(audit_path)},
        }
    )


def _client(audit_path: Path, *, token: str | None = None) -> TestClient:
    return TestClient(build_dashboard_app(_config(audit_path), token=token))


# ------------- summary -------------


def test_summarize_counts_outcomes_and_duration() -> None:
    summary = _summarize(
        [
            {"outcome": "ok", "duration_ms": 10.0},
            {"outcome": "ok", "duration_ms": 5.0},
            {"outcome": "denied", "duration_ms": 1.0},
            {"outcome": "error", "duration_ms": 2.0},
        ]
    )
    assert summary["total"] == 4
    assert summary["ok"] == 2
    assert summary["denied"] == 1
    assert summary["errors"] == 1
    assert summary["total_ms"] == 18.0


def test_summarize_totals_spend() -> None:
    summary = _summarize([{"cost": 0.01}, {"cost": 0.02}, {"cost": None}])
    assert summary["spend"] == 0.03


def test_summarize_counts_flagged_calls_and_reasons() -> None:
    summary = _summarize(
        [
            {"flags": ["injection:instruction-override"]},
            {"flags": ["injection:instruction-override", "secret:github-token"]},
            {"flags": None},
        ]
    )
    assert summary["flagged"] == 2
    assert summary["top_flags"][0] == {"name": "injection:instruction-override", "count": 2}


def test_summarize_ranks_tools_by_call_count() -> None:
    summary = _summarize([{"tool": "a"}, {"tool": "a"}, {"tool": "b"}])
    assert summary["top_tools"][0] == {"name": "a", "calls": 2}


def test_summarize_tolerates_junk_numbers() -> None:
    """A hand-edited log must not take the dashboard down."""
    summary = _summarize([{"duration_ms": "not a number", "cost": {}}])
    assert summary["total_ms"] == 0.0
    assert summary["spend"] == 0.0


def test_summarize_handles_an_empty_log() -> None:
    summary = _summarize([])
    assert summary["total"] == 0
    assert summary["top_tools"] == []


# ------------- serving -------------


def test_dashboard_serves_index(tmp_path: Path) -> None:
    response = _client(tmp_path / "audit.jsonl").get("/")
    assert response.status_code == 200
    assert "Bastion" in response.text


def test_dashboard_api_returns_records_newest_first(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(f"{_record('echo')}\n{_record('boom', outcome='error')}\n", encoding="utf-8")

    data = _client(log).get("/api/audit").json()

    assert data["summary"]["total"] == 2
    assert data["summary"]["errors"] == 1
    assert data["records"][0]["tool"] == "boom"


def test_dashboard_picks_up_appended_records(tmp_path: Path) -> None:
    """The incremental reader must not miss anything written after the first poll."""
    log = tmp_path / "audit.jsonl"
    log.write_text(f"{_record('first')}\n", encoding="utf-8")
    client = _client(log)
    assert client.get("/api/audit").json()["summary"]["total"] == 1

    with log.open("a", encoding="utf-8") as handle:
        handle.write(f"{_record('second')}\n")

    data = client.get("/api/audit").json()
    assert data["summary"]["total"] == 2
    assert data["records"][0]["tool"] == "second"


def test_dashboard_recovers_when_the_log_is_rotated(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(f"{_record('old')}\n" * 5, encoding="utf-8")
    client = _client(log)
    assert client.get("/api/audit").json()["summary"]["total"] == 5

    log.replace(tmp_path / "audit.jsonl.1")
    log.write_text(f"{_record('fresh')}\n", encoding="utf-8")

    data = client.get("/api/audit").json()
    assert data["summary"]["total"] == 1
    assert data["records"][0]["tool"] == "fresh"


def test_dashboard_reports_a_healthy_chain(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    with AuditWriter(log) as writer:
        writer.write(AuditRecord(tool="a"))
        writer.write(AuditRecord(tool="b"))

    chain = _client(log).get("/api/audit").json()["chain"]
    assert chain["ok"]
    assert chain["checked"] == 2


def test_dashboard_reports_a_broken_chain(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    with AuditWriter(log) as writer:
        writer.write(AuditRecord(tool="a"))
        writer.write(AuditRecord(tool="b"))
    lines = log.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["tool"] = "c"
    log.write_text(lines[0] + "\n" + json.dumps(tampered) + "\n", encoding="utf-8")

    chain = _client(log).get("/api/audit").json()["chain"]
    assert not chain["ok"]
    assert chain["problem"]


# ------------- access token -------------


def test_a_token_is_required_when_one_is_set(tmp_path: Path) -> None:
    client = _client(tmp_path / "audit.jsonl", token=TOKEN)
    assert client.get("/").status_code == 401
    assert client.get("/api/audit").status_code == 401


def test_the_right_token_is_accepted(tmp_path: Path) -> None:
    client = _client(tmp_path / "audit.jsonl", token=TOKEN)
    assert client.get(f"/?t={TOKEN}").status_code == 200
    assert client.get(f"/api/audit?t={TOKEN}").status_code == 200


def test_a_wrong_token_is_rejected(tmp_path: Path) -> None:
    client = _client(tmp_path / "audit.jsonl", token=TOKEN)
    assert client.get("/api/audit?t=not-the-token").status_code == 401


def test_the_token_can_be_supplied_as_a_header(tmp_path: Path) -> None:
    client = _client(tmp_path / "audit.jsonl", token=TOKEN)
    response = client.get("/api/audit", headers={"x-bastion-token": TOKEN})
    assert response.status_code == 200


def test_a_rejected_request_leaks_no_records(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(f"{_record('sensitive_tool')}\n", encoding="utf-8")
    response = _client(log, token=TOKEN).get("/api/audit")
    assert "sensitive_tool" not in response.text


def test_a_non_ascii_token_is_refused_rather_than_crashing(tmp_path: Path) -> None:
    """compare_digest rejects non-ASCII str; that must be a 401, not a 500."""
    client = _client(tmp_path / "audit.jsonl", token=TOKEN)
    assert client.get("/api/audit?t=🔑🔑🔑").status_code == 401


def test_only_the_most_recent_records_are_returned(tmp_path: Path) -> None:
    from bastion.dashboard.app import RECENT_LIMIT

    log = tmp_path / "audit.jsonl"
    log.write_text(
        "".join(f"{_record(f't{i}')}\n" for i in range(RECENT_LIMIT + 25)), encoding="utf-8"
    )

    data = _client(log).get("/api/audit").json()

    assert data["summary"]["total"] == RECENT_LIMIT + 25  # counted in full
    assert len(data["records"]) == RECENT_LIMIT  # but not all returned


# ------------- the incremental view must match the batch one -------------


def test_the_summary_matches_recomputing_it_from_scratch(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    client = _client(log)

    written: list[dict[str, Any]] = []
    for index in range(12):
        record = {
            "tool": f"t{index % 3}",
            "outcome": ["ok", "denied", "error"][index % 3],
            "duration_ms": float(index),
            "cost": 0.01,
            "flags": ["injection:x"] if index % 4 == 0 else None,
        }
        written.append(record)
        with log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        client.get("/api/audit")  # poll after each append, as the page does

    incremental = client.get("/api/audit").json()["summary"]
    batch = _summarize(written)

    for key in ("total", "ok", "denied", "errors", "flagged", "total_ms", "spend"):
        assert incremental[key] == batch[key], key
    assert incremental["top_tools"] == batch["top_tools"]
    assert incremental["top_flags"] == batch["top_flags"]


def test_the_summary_resets_when_the_log_is_replaced(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(f"{_record('old')}\n" * 6, encoding="utf-8")
    client = _client(log)
    assert client.get("/api/audit").json()["summary"]["total"] == 6

    log.write_text(f"{_record('fresh')}\n", encoding="utf-8")
    summary = client.get("/api/audit").json()["summary"]
    assert summary["total"] == 1
    assert summary["top_tools"] == [{"name": "fresh", "calls": 1}]


def test_a_non_finite_value_in_an_old_log_does_not_break_the_api(tmp_path: Path) -> None:
    """Logs written before non-finite values were sanitised still have to load."""
    log = tmp_path / "audit.jsonl"
    log.write_text(
        '{"tool":"calc","outcome":"ok","duration_ms":1.0,"arguments":{"x":Infinity}}\n',
        encoding="utf-8",
    )
    response = _client(log).get("/api/audit")
    assert response.status_code == 200


# ------------- tampering with records already seen -------------


def _counted(tmp_path: Path) -> "Callable[[], int]":
    """Count calls to the chain verifier the dashboard uses."""
    import bastion.dashboard.app as app_module

    calls = [0]
    original = app_module.verify_records

    def counting(records: object) -> object:
        calls[0] += 1
        return original(records)  # type: ignore[arg-type]

    app_module.verify_records = counting  # type: ignore[assignment]
    _RESTORE.append(lambda: setattr(app_module, "verify_records", original))
    return lambda: calls[0]


_RESTORE: list["Callable[[], None]"] = []


@pytest.fixture(autouse=True)
def _restore_patches() -> "Iterator[None]":
    yield
    while _RESTORE:
        _RESTORE.pop()()


def _chained(log: Path, count: int) -> None:
    with AuditWriter(log) as writer:
        for index in range(count):
            writer.write(AuditRecord(tool=f"t{index}"))


def _edit_record(log: Path, index: int) -> None:
    lines = log.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[index])
    record["tool"] = "innocuous"
    lines[index] = json.dumps(record)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_editing_a_record_the_dashboard_already_saw_is_detected(tmp_path: Path) -> None:
    """Verifying only new records never looks at one twice, and missed exactly this."""
    log = tmp_path / "audit.jsonl"
    _chained(log, 6)

    clock = [0.0]
    client = TestClient(build_dashboard_app(_config(log), now=lambda: clock[0]))
    assert client.get("/api/audit").json()["chain"]["ok"]

    _edit_record(log, 1)
    clock[0] += VERIFY_INTERVAL_SECONDS + 0.1

    chain = client.get("/api/audit").json()["chain"]
    assert not chain["ok"]
    assert chain["problem"]


def test_verification_is_throttled_between_rapid_polls(tmp_path: Path) -> None:
    """The page polls every 1.5s; re-hashing the whole log each time is the cost being avoided."""
    log = tmp_path / "audit.jsonl"
    _chained(log, 4)

    clock = [0.0]
    verifications = _counted(tmp_path)
    client = TestClient(build_dashboard_app(_config(log), now=lambda: clock[0]))

    for _ in range(6):
        client.get("/api/audit")  # all within one interval
    assert verifications() == 1

    clock[0] += VERIFY_INTERVAL_SECONDS + 0.1
    client.get("/api/audit")
    assert verifications() == 2


def test_a_new_record_is_visible_before_the_next_verification(tmp_path: Path) -> None:
    """Throttling verification must not delay the records themselves."""
    log = tmp_path / "audit.jsonl"
    _chained(log, 2)

    clock = [0.0]
    client = TestClient(build_dashboard_app(_config(log), now=lambda: clock[0]))
    assert client.get("/api/audit").json()["summary"]["total"] == 2

    with AuditWriter(log) as writer:
        writer.write(AuditRecord(tool="just_now"))

    data = client.get("/api/audit").json()  # same instant, no re-verification
    assert data["summary"]["total"] == 3
    assert data["records"][0]["tool"] == "just_now"
