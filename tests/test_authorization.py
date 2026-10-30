from conftest import P, deliver, read, save


def test_authorized_flow_succeeds(env):
    assert read(env, "q3_financials.md").allowed
    assert save(env, "q3_summary").allowed
    r = deliver(env, "q3_summary", "internal@corp.example")
    assert r.allowed and r.executed
    assert [m["recipient"] for m in env.store.list_outbox()] == ["internal@corp.example"]


def test_unknown_principal_denied(env):
    r = env.gate.submit(P(principal="eve", operation="read_document", resource="public_faq.md"))
    assert not r.allowed and r.decision.rule == "unknown_principal"


def test_role_without_permission_denied(env):
    r = env.gate.submit(P(principal="mallory", operation="deliver_inbox", resource="x",
                          recipient="internal@corp.example"))
    assert not r.allowed and r.decision.rule == "role_not_permitted"


def test_read_above_clearance_denied(env):
    r = read(env, "merger_plan.md")  # bob is analyst: up to CONFIDENTIAL
    assert not r.allowed and r.decision.rule == "insufficient_clearance"


def test_admin_can_read_secret(env):
    r = env.gate.submit(P(principal="alice", operation="read_document", resource="merger_plan.md"))
    assert r.allowed


def test_unregistered_document_denied(env):
    r = read(env, "../../etc/passwd")
    assert not r.allowed and r.decision.rule == "document_not_registered"


def test_unregistered_recipient_denied(env):
    read(env, "public_faq.md")
    save(env, "faq_note")
    r = deliver(env, "faq_note", "attacker@evil.example")
    assert not r.allowed and r.decision.rule == "recipient_not_authorized"


def test_self_asserted_label_is_rejected_by_schema(env):
    bad = {"principal": "bob", "workflow_id": "wf-test", "operation": "save_report",
           "resource": "r", "content": "x", "sensitivity": "PUBLIC"}
    r = env.gate.submit(bad)
    assert not r.allowed and r.decision.rule == "schema_validation"
    assert env.calls["save_report"] == 0


def test_unknown_operation_rejected_by_schema(env):
    r = env.gate.submit({"principal": "bob", "workflow_id": "w", "operation": "delete_everything",
                         "resource": "x"})
    assert not r.allowed and r.decision.rule == "schema_validation"


def test_workflow_is_bound_to_its_principal(env):
    read(env, "public_faq.md")  # binds wf-test to bob
    r = env.gate.submit(P(principal="alice", operation="read_document", resource="public_faq.md"))
    assert not r.allowed and r.decision.rule == "workflow_owner"
