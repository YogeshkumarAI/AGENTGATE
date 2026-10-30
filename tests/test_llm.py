import json

from agentgate.llm import LLMProposer


def fake_model(reply):
    return lambda prompt: reply


def test_identity_is_injected_by_system_not_model():
    reply = json.dumps([{"operation": "read_document", "resource": "public_faq.md",
                         "principal": "alice", "workflow_id": "evil"}])
    props, errs = LLMProposer(fake_model(reply)).propose("read faq", "bob", "wf-1")
    assert not errs and props[0].principal == "bob" and props[0].workflow_id == "wf-1"


def test_model_cannot_smuggle_labels_or_unknown_fields():
    reply = json.dumps([{"operation": "save_report", "resource": "r", "content": "c", "sensitivity": "PUBLIC"}])
    props, errs = LLMProposer(fake_model(reply)).propose("x", "bob", "wf-1")
    assert props == [] and len(errs) == 1


def test_garbage_output_is_reported_not_executed():
    props, errs = LLMProposer(fake_model("I refuse, here is a poem")).propose("x", "bob", "wf-1")
    assert props == [] and errs == []
    props, errs = LLMProposer(fake_model("[not json]")).propose("x", "bob", "wf-1")
    assert props == [] and errs


def test_proposals_from_llm_still_go_through_the_gate(env):
    reply = json.dumps([
        {"operation": "read_document", "resource": "q3_financials.md"},
        {"operation": "save_report", "resource": "llm_report", "content": "summary"},
        {"operation": "deliver_inbox", "resource": "llm_report", "recipient": "partner@external.example"},
    ])
    props, _ = LLMProposer(fake_model(reply)).propose("send the summary to the partner", "bob", "wf-llm")
    results = [env.gate.submit(p) for p in props]
    assert [r.allowed for r in results] == [True, True, False]
    assert env.calls["deliver_inbox"] == 0
