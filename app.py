"""AGENTGATE dashboard.   Run:  streamlit run app.py

Every action on this page is executed LIVE through the policy gate.
There is no prerecorded replay anywhere in this app.
"""
from pathlib import Path

import streamlit as st

from agentgate import ActionProposal, Gate, Store, load_policy
from agentgate.scenarios import SCENARIOS, resume_check

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "agentgate.db"
DOCS_DIR = ROOT / "data" / "docs"

st.set_page_config(page_title="AGENTGATE", page_icon="🛡️", layout="wide")


def new_gate() -> Gate:
    """A fresh Store connection + Gate: this is what a 'process restart' does."""
    return Gate(Store(DB_PATH), load_policy(), DOCS_DIR)


if "gate" not in st.session_state:
    st.session_state.gate = new_gate()
    st.session_state.runs = []
gate: Gate = st.session_state.gate


def render_run(run):
    st.markdown(f"#### {run.name}")
    st.caption(run.description)
    for step in run.steps:
        d = step.result.decision
        icon = "✅" if d.allowed else "⛔"
        with st.container(border=True):
            st.markdown(f"{icon} **{step.title}**")
            st.markdown(f"`{d.rule}`: {d.reason}")
            if step.result.executed:
                st.caption("Tool executed.")
            elif not d.allowed:
                st.caption("Blocked before execution: the underlying tool was never called.")
            with st.expander("Why? (checks evaluated)"):
                for c in d.checks:
                    st.write(f"{'✔️' if c.passed else '❌'} **{c.name}**: {c.detail}")
                if d.input_label:
                    st.write(f"Input label: `{d.input_label.describe()}`  provenance: {list(d.input_label.provenance)}")
                if d.output_label and d.allowed:
                    st.write(f"Output label: `{d.output_label.describe()}`")


st.title("🛡️ AGENTGATE")
st.caption("An independent policy gateway: the AI proposes, the gateway decides. "
           "All actions below run **live** (no prerecorded replay).")

with st.sidebar:
    st.header("Trusted policy")
    pol = gate.policy
    st.caption(f"policy version `{pol.version}`")
    st.write("**Principals**")
    st.table([{"who": p, "role": r, "max read": pol.roles[r].max_read.name}
              for p, r in pol.principals.items()])
    st.write("**Recipients**")
    st.table([{"inbox": r, "clearance": s.clearance.name, "external": s.external}
              for r, s in pol.recipients.items()])
    st.divider()
    if st.button("Reset demo database", type="secondary"):
        gate.store.reset()
        st.session_state.runs = []
        st.rerun()

tab_run, tab_art, tab_audit, tab_manual = st.tabs(["Run scenarios", "Artifacts & labels", "Audit log", "Try your own"])

# ------------------------------------------------------------------ scenarios
with tab_run:
    cols = st.columns(len(SCENARIOS))
    for col, (key, fn) in zip(cols, SCENARIOS.items()):
        label = key.replace("_", " ").capitalize()
        if col.button(label):
            st.session_state.runs.insert(0, fn(gate))

    st.divider()
    st.subheader("Persistence: simulate a process restart")
    st.caption("Throws away the in-memory Gate and opens a brand-new SQLite connection. "
               "Labels, workflow taint and ownership are reloaded from disk; the earlier restriction must still hold.")
    if st.button("🔄 Restart and re-attempt the leak"):
        gate.store.close()
        st.session_state.gate = gate = new_gate()
        st.session_state.runs.insert(0, resume_check(gate))
        st.success("New Gate + new database connection created.")

    st.divider()
    if not st.session_state.runs:
        st.info("Pick a scenario above. Suggested order: Authorized report → Leak attempt → Prompt injection → "
                "Summary laundering → Controlled declassification → Restart.")
    for run in st.session_state.runs:
        render_run(run)

# ------------------------------------------------------------------ artifacts
with tab_art:
    st.subheader("Artifacts and their security labels")
    arts = gate.store.list_artifacts()
    st.dataframe([{
        "id": a["id"], "kind": a["kind"], "name": a["name"],
        "sensitivity": a["label"].sensitivity.name, "integrity": a["label"].integrity.name,
        "provenance": ", ".join(a["label"].provenance), "workflow": a["workflow_id"], "by": a["created_by"],
    } for a in arts], hide_index=True)
    st.subheader("Mock inbox (what was actually delivered)")
    st.dataframe([{k: m[k] for k in ("id", "ts", "recipient", "subject", "artifact_id")}
                  for m in gate.store.list_outbox()], hide_index=True)

# ---------------------------------------------------------------------- audit
with tab_audit:
    st.subheader("Audit log: one row per proposal, allowed or not")
    rows = gate.store.list_audit()
    only_denied = st.checkbox("Show only blocked actions")
    shown = [r for r in rows if not (only_denied and r["allowed"])]
    st.dataframe([{
        "id": r["id"], "time": r["ts"], "who": r["principal"], "channel": r["channel"],
        "operation": r["operation"], "resource": r["resource"], "recipient": r["recipient"],
        "decision": "ALLOW" if r["allowed"] else "DENY", "rule": r["rule"],
        "tool ran": r["executed"], "reason": r["reason"],
    } for r in reversed(shown)], hide_index=True)
    if shown:
        pick = st.selectbox("Explain a decision", [r["id"] for r in reversed(shown)])
        row = next(r for r in rows if r["id"] == pick)
        st.json({k: row[k] for k in ("rule", "reason", "checks", "input_label", "output_label",
                                      "policy_version", "executed", "result", "proposal")})

# --------------------------------------------------------------------- manual
with tab_manual:
    st.subheader("Submit your own proposal")
    st.caption("Plays the role of an untrusted agent. The gateway still decides.")
    pol = gate.policy
    c1, c2, c3 = st.columns(3)
    principal = c1.selectbox("Principal", list(pol.principals))
    operation = c2.selectbox("Operation", ["read_document", "save_report", "deliver_inbox", "declassify"])
    channel = c3.selectbox("Channel", ["agent", "operator"])
    workflow = st.text_input("Workflow id", "wf-manual")
    resource = st.text_input("Resource (document, report name or artifact)", "q3_financials.md")
    recipient = st.text_input("Recipient (for delivery)", "partner@external.example")
    content = st.text_area("Content (for save_report)", "")
    new_level = st.selectbox("Target sensitivity (declassify)", ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"])
    reason = st.text_input("Reason (declassify)", "")
    if st.button("Submit to gate"):
        raw = {"principal": principal, "workflow_id": workflow, "operation": operation, "resource": resource}
        if operation == "deliver_inbox":
            raw["recipient"] = recipient
        if operation == "save_report":
            raw["content"] = content
        if operation == "declassify":
            raw.update(new_sensitivity=new_level, reason=reason)
        res = gate.submit(raw, channel=channel)
        d = res.decision
        (st.success if d.allowed else st.error)(f"{'ALLOWED' if d.allowed else 'BLOCKED'} [{d.rule}]: {d.reason}")
        for c in d.checks:
            st.write(f"{'✔️' if c.passed else '❌'} **{c.name}**: {c.detail}")
