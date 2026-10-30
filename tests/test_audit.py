from agentgate import Gate
from agentgate.scenarios import SCENARIOS
from conftest import P, deliver, read, save

REQUIRED = ("ts", "workflow_id", "principal", "channel", "operation", "resource", "allowed",
            "rule", "reason", "checks", "policy_version", "proposal")


def test_every_submission_writes_exactly_one_audit_row(env):
    read(env, "q3_financials.md")                                        # allowed
    read(env, "merger_plan.md")                                          # denied
    save(env, "r")                                                       # allowed
    deliver(env, "r", "partner@external.example")                        # denied
    env.gate.submit({"principal": "bob", "operation": "nope"})           # malformed
    rows = env.store.list_audit()
    assert len(rows) == 5
    assert [r["allowed"] for r in rows] == [True, False, True, False, False]


def test_audit_rows_are_complete_and_explain_the_decision(env):
    read(env, "q3_financials.md")
    save(env, "r")
    deliver(env, "r", "partner@external.example")
    for row in env.store.list_audit():
        for key in REQUIRED:
            assert row[key] not in (None, ""), f"missing {key}"
        assert row["checks"], "decision must list the checks that were evaluated"
    denied = env.store.list_audit()[-1]
    assert denied["rule"] == "information_flow_violation"
    assert any(c["name"] == "information_flow" and not c["passed"] for c in denied["checks"])
    assert denied["recipient"] == "partner@external.example"
    assert denied["input_label"]["sensitivity"] == "CONFIDENTIAL"
    assert denied["executed"] is False


def test_executed_flag_matches_reality(env):
    read(env, "q3_financials.md")
    save(env, "r")
    deliver(env, "r", "partner@external.example")
    deliver(env, "r", "internal@corp.example")
    rows = env.store.list_audit()
    assert [r["executed"] for r in rows] == [True, True, False, True]


def test_audit_is_written_before_the_tool_runs(env):
    seen = {}
    real = env.tools["read_document"]

    def probing_tool(**kw):
        rows = env.store.list_audit()
        seen["rows_at_call_time"] = len(rows)
        seen["executed_flag_at_call_time"] = rows[-1]["executed"]
        return real(**kw)

    gate = Gate(env.store, env.policy, env.gate.docs_dir, tools={**env.tools, "read_document": probing_tool})
    gate.submit(P(operation="read_document", resource="public_faq.md"))
    assert seen["rows_at_call_time"] == 1 and seen["executed_flag_at_call_time"] is False
    assert env.store.list_audit()[0]["executed"] is True


def test_policy_version_is_recorded(env):
    read(env, "public_faq.md")
    assert env.store.list_audit()[0]["policy_version"] == env.policy.version != ""


def test_all_scenarios_leave_a_complete_trail(env):
    total = 0
    for fn in SCENARIOS.values():
        run = fn(env.gate)
        total += len(run.steps)
        for step in run.steps:
            assert step.result.audit_id is not None
            assert step.result.decision.reason
    assert len(env.store.list_audit()) == total
