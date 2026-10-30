from agentgate import Integrity, Sensitivity, can_flow_to, derive, join
from agentgate.models import Label
from conftest import P, deliver, read, save


def test_confidential_report_blocked_for_external_allowed_for_internal(env):
    read(env, "q3_financials.md")
    save(env, "q3_report")
    blocked = deliver(env, "q3_report", "partner@external.example")
    assert not blocked.allowed and blocked.decision.rule == "information_flow_violation"
    assert deliver(env, "q3_report", "internal@corp.example").allowed


def test_report_inherits_label_from_what_was_read(env):
    read(env, "q3_financials.md")
    r = save(env, "q3_report")
    assert r.decision.output_label.sensitivity == Sensitivity.CONFIDENTIAL
    art = env.store.resolve("q3_report")
    assert art["label"].sensitivity == Sensitivity.CONFIDENTIAL
    assert "doc:q3_financials.md" in art["label"].provenance


def test_summary_cannot_launder_label_by_declaring_no_parents(env):
    env.gate.submit(P(principal="alice", operation="read_document", resource="merger_plan.md"))
    r = env.gate.submit(P(principal="alice", operation="save_report", resource="innocent",
                          content="a harmless-looking summary", parents=[]))
    assert r.decision.output_label.sensitivity == Sensitivity.SECRET
    for who in ("partner@external.example", "internal@corp.example"):
        d = env.gate.submit(P(principal="alice", operation="deliver_inbox", resource="innocent", recipient=who))
        assert not d.allowed
    ok = env.gate.submit(P(principal="alice", operation="deliver_inbox", resource="innocent",
                           recipient="secure@corp.example"))
    assert ok.allowed


def test_derived_label_is_join_of_parents():
    a = Label(sensitivity=Sensitivity.INTERNAL, integrity=Integrity.TRUSTED, provenance=("doc:a",))
    b = Label(sensitivity=Sensitivity.CONFIDENTIAL, integrity=Integrity.UNTRUSTED, provenance=("doc:b",))
    j = join([a, b])
    assert j.sensitivity == Sensitivity.CONFIDENTIAL and j.integrity == Integrity.UNTRUSTED
    assert set(j.provenance) == {"doc:a", "doc:b"}
    assert derive([a], ["art:1"]).provenance == ("art:1", "doc:a")


def test_flow_rule():
    lbl = Label(sensitivity=Sensitivity.CONFIDENTIAL, integrity=Integrity.TRUSTED)
    assert can_flow_to(lbl, Sensitivity.CONFIDENTIAL) and can_flow_to(lbl, Sensitivity.SECRET)
    assert not can_flow_to(lbl, Sensitivity.INTERNAL)


def test_parent_above_clearance_cannot_be_used(env):
    env.gate.submit(P(principal="alice", operation="read_document", resource="merger_plan.md",
                      workflow_id="wf-a"))
    env.gate.submit(P(principal="alice", operation="save_report", resource="secret_note",
                      content="s", workflow_id="wf-a"))
    r = env.gate.submit(P(principal="bob", operation="save_report", resource="bob_note",
                          content="derived", parents=["secret_note"], workflow_id="wf-b"))
    assert not r.allowed and r.decision.rule == "insufficient_clearance"


def test_unknown_parent_denied(env):
    r = save(env, "x", parents=["does_not_exist"])
    assert not r.allowed and r.decision.rule == "unknown_parent"


def test_declared_parent_label_flows_into_report(env):
    env.gate.submit(P(principal="alice", operation="read_document", resource="q3_financials.md",
                      workflow_id="wf-a"))
    env.gate.submit(P(principal="alice", operation="save_report", resource="base", content="b",
                      workflow_id="wf-a"))
    r = env.gate.submit(P(principal="bob", operation="save_report", resource="derived",
                          content="d", parents=["base"], workflow_id="wf-b"))
    assert r.allowed and r.decision.output_label.sensitivity == Sensitivity.CONFIDENTIAL


def test_untrusted_content_cannot_go_to_external_recipient_even_if_public(env):
    read(env, "vendor_note.md")  # PUBLIC but UNTRUSTED
    r = deliver(env, "vendor_note.md", "partner@external.example")
    assert not r.allowed and r.decision.rule == "untrusted_to_external"


def test_untrusted_taint_propagates_to_reports(env):
    read(env, "vendor_note.md")
    r = save(env, "from_vendor")
    assert r.decision.output_label.integrity == Integrity.UNTRUSTED
