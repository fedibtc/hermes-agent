import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.correspondence_evaluator import evaluate_correspondence
from gateway.owner_audit import read_recent_audit_events
from gateway.permissions import PermissionResolver


CONFIG = {
    "owners": {
        "owner": {
            "principals": ["telegram:owner"],
            "default_correspondent_policy": "coworker",
        }
    },
    "principals": {
        "telegram:employee": {
            "relationship": "coworker",
            "subject_owner": "owner",
        }
    },
    "policies": {"coworker": {"tools": {"allow": ["clarify"]}}},
}


def _source(user_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        platform="telegram",
        user_id=user_id,
        user_id_alt=None,
        user_name=user_id,
        chat_type="dm",
    )


def test_owner_response_is_allowed():
    ctx = PermissionResolver(CONFIG).resolve(_source("owner"), session_key="s")

    result = evaluate_correspondence(
        "Authorization: Bearer test-token",
        permission_context=ctx,
    )

    assert result.decision == "allow"


def test_non_owner_secret_leak_is_replaced():
    ctx = PermissionResolver(CONFIG).resolve(_source("employee"), session_key="s")

    result = evaluate_correspondence(
        "Use Authorization: Bearer secret-token-123456",
        permission_context=ctx,
    )

    assert result.decision == "ask_owner"
    assert result.risk == "high"
    assert "privacy" in result.violations
    assert "can't share owner-private" in result.safe_response


def test_non_owner_evaluation_writes_owner_audit(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    ctx = PermissionResolver(CONFIG).resolve(_source("employee"), session_key="s")

    result = evaluate_correspondence(
        "Use Authorization: Bearer secret-token-123456",
        permission_context=ctx,
    )

    assert result.decision == "ask_owner"
    events = read_recent_audit_events("owner", limit=5)
    assert len(events) == 1
    assert events[0]["event_type"] == "correspondence_evaluated"
    assert events[0]["requester"] == "telegram:employee"
    assert events[0]["details"]["decision"] == "ask_owner"
    assert events[0]["details"]["risk"] == "high"


def test_non_owner_owner_intent_claim_requires_approval():
    ctx = PermissionResolver(CONFIG).resolve(_source("employee"), session_key="s")

    result = evaluate_correspondence(
        "The owner thinks this contract is approved.",
        permission_context=ctx,
    )

    assert result.decision == "ask_owner"
    assert result.risk == "medium"
    assert "authority" in result.violations


def test_safe_scheduling_reply_is_allowed():
    ctx = PermissionResolver(CONFIG).resolve(_source("employee"), session_key="s")

    result = evaluate_correspondence(
        "I can ask the owner about Tuesday at 10:00.",
        permission_context=ctx,
    )

    assert result.decision == "allow"


def test_non_owner_calendar_hold_side_effect_requires_approval():
    ctx = PermissionResolver(CONFIG).resolve(_source("employee"), session_key="s")

    result = evaluate_correspondence(
        "Done.",
        permission_context=ctx,
        messages=[
            {
                "role": "assistant",
                "tool_calls": [
                    {"function": {"name": "calendar_hold"}},
                ],
            }
        ],
    )

    assert result.decision == "ask_owner"
    assert result.risk == "medium"
    assert "authority" in result.violations


def _redteam_cases():
    fixture_path = Path(__file__).parent / "fixtures" / "owner_correspondence_redteam.json"
    return json.loads(fixture_path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _redteam_cases(), ids=lambda case: case["id"])
def test_owner_correspondence_redteam_corpus(case, monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    ctx = PermissionResolver(CONFIG).resolve(_source("employee"), session_key=f"case:{case['id']}")

    result = evaluate_correspondence(
        case["response"],
        permission_context=ctx,
        messages=case.get("messages"),
    )

    assert result.decision == case["expected_decision"]
    assert result.risk == case["expected_risk"]
    for violation in case["expected_violations"]:
        assert violation in result.violations
    if not case["expected_violations"]:
        assert result.violations == ()
