from agentgate import Sensitivity
from conftest import P, deliver


def _make_confidential_report(env):
    env.gate.submit(P(principal="alice", operation="read_document", resource="q3_financials.md"))
    env.gate.submit(P(principal="alice", operation="save_report", resource="blurb", content="growth"))


def _declassify(env, principal="alice", channel="operator", reason="approved by comms lead"):
    wf = "wf-test" if principal == "alice" else f"wf-{principal}"
    return env.gate.submit(P(principal=principal, workflow_id=wf, operation="declassify",
                             resource="blurb", new_sensitivity="PUBLIC", reason=reason), channel=channel)


def test_agent_channel_cannot_declassify(env):
    _make_confidential_report(env)
    r = _declassify(env, channel="agent")
    assert not r.allowed and r.decision.rule == "declassify_requires_operator"


def test_unprivileged_role_cannot_declassify_even_as_operator(env):
    _make_confidential_report(env)
    r = _declassify(env, principal="bob")
    assert not r.allowed and r.decision.rule == "role_not_permitted"


def test_reason_is_mandatory(env):
    _make_confidential_report(env)
    r = _declassify(env, reason="  ")
    assert not r.allowed and r.decision.rule == "declassify_requires_reason"


def test_authorized_operator_can_declassify_and_it_is_audited(env):
    _make_confidential_report(env)
    assert not deliver(env, "blurb", "partner@external.example", principal="alice").allowed
    r = _declassify(env)
    assert r.allowed
    label = env.store.resolve("blurb")["label"]
    assert label.sensitivity == Sensitivity.PUBLIC
    assert "declassified-by:alice" in label.provenance
    assert deliver(env, "blurb", "partner@external.example", principal="alice").allowed
    entry = [a for a in env.store.list_audit() if a["operation"] == "declassify" and a["allowed"]][0]
    assert entry["channel"] == "operator" and "comms lead" in entry["reason"]
    assert entry["input_label"]["sensitivity"] == "CONFIDENTIAL"
    assert entry["output_label"]["sensitivity"] == "PUBLIC"
