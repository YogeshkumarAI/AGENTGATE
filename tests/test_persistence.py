from agentgate import Sensitivity
from agentgate.scenarios import leak_attempt, resume_check
from conftest import deliver, read, reopen, save


def test_restrictions_survive_process_restart(env):
    read(env, "q3_financials.md")
    save(env, "q3_report")
    before = env.store.resolve("q3_report")["label"]
    assert before.sensitivity == Sensitivity.CONFIDENTIAL

    env = reopen(env)  # brand-new connection + Gate, same SQLite file
    after = env.store.resolve("q3_report")["label"]
    assert after == before

    blocked = deliver(env, "q3_report", "partner@external.example")
    assert not blocked.allowed and blocked.decision.rule == "information_flow_violation"
    assert deliver(env, "q3_report", "internal@corp.example").allowed


def test_workflow_taint_survives_resume(env):
    read(env, "q3_financials.md")  # workflow wf-test now carries CONFIDENTIAL
    env = reopen(env)
    r = save(env, "after_resume", content="written after the restart")
    assert r.decision.output_label.sensitivity == Sensitivity.CONFIDENTIAL


def test_workflow_ownership_survives_resume(env):
    from conftest import P
    read(env, "public_faq.md")
    env = reopen(env)
    r = env.gate.submit(P(principal="alice", operation="read_document", resource="public_faq.md"))
    assert r.decision.rule == "workflow_owner" and not r.allowed


def test_provenance_survives_restart(env):
    read(env, "q3_financials.md")
    save(env, "q3_report")
    env = reopen(env)
    assert "doc:q3_financials.md" in env.store.resolve("q3_report")["label"].provenance


def test_resume_scenario_blocks_after_restart(env):
    leak_attempt(env.gate)
    env = reopen(env)
    run = resume_check(env.gate)
    assert not run.steps[-1].result.allowed
    assert env.store.list_outbox() == []
