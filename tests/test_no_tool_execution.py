"""Core guarantee: a blocked action never reaches the underlying tool."""
import pytest

from agentgate import Sensitivity
from conftest import P, deliver, read, save


def test_denied_read_never_calls_tool(env):
    r = read(env, "merger_plan.md")
    assert not r.allowed
    assert env.calls["read_document"] == 0


def test_denied_save_never_calls_tool(env):
    r = save(env, "bad name with spaces!")
    assert not r.allowed
    assert env.calls["save_report"] == 0
    assert env.store.list_artifacts() == []


def test_denied_delivery_never_calls_tool_and_outbox_stays_empty(env):
    read(env, "q3_financials.md")
    save(env, "q3_report")
    for who in ("partner@external.example", "attacker@evil.example"):
        r = deliver(env, "q3_report", who)
        assert not r.allowed and not r.executed
    assert env.calls["deliver_inbox"] == 0
    assert env.store.list_outbox() == []


def test_allowed_actions_do_reach_tools_exactly_once(env):
    read(env, "q3_financials.md")
    save(env, "q3_report")
    deliver(env, "q3_report", "internal@corp.example")
    assert (env.calls["read_document"], env.calls["save_report"], env.calls["deliver_inbox"]) == (1, 1, 1)


@pytest.mark.parametrize("bad", [
    {"principal": "bob", "workflow_id": "w", "operation": "deliver_inbox", "resource": "x", "label": "PUBLIC"},
    {"principal": "", "workflow_id": "w", "operation": "read_document", "resource": "public_faq.md"},
    {"principal": "bob", "workflow_id": "w", "operation": "format_disk", "resource": "x"},
    {"principal": "bob", "workflow_id": "w", "operation": "read_document"},
])
def test_malformed_proposals_never_reach_any_tool(env, bad):
    r = env.gate.submit(bad)
    assert not r.allowed
    assert sum(env.calls.values()) == 0


def test_declassify_denied_for_agent_never_changes_label(env):
    env.gate.submit(P(principal="alice", operation="read_document", resource="q3_financials.md"))
    env.gate.submit(P(principal="alice", operation="save_report", resource="r", content="c"))
    env.gate.submit(P(principal="alice", operation="declassify", resource="r", new_sensitivity="PUBLIC",
                      reason="trust me"), channel="agent")
    assert env.store.resolve("r")["label"].sensitivity == Sensitivity.CONFIDENTIAL
