# AGENTGATE

An independent policy gateway for tool-using AI agents. The AI **proposes** actions; the gateway
**decides**, using trusted policy and persistent security labels. A blocked action never reaches the tool.

## Quick start (VS Code)

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate        macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt

pytest                    # 52 tests: authorization, information flow, injection, persistence, audit
streamlit run app.py      # dashboard
```

## Layout

```
agentgate/
  models.py      Pydantic: Label, ActionProposal (extra fields forbidden), Decision, Policy
  labels.py      join() / derive() / can_flow_to()   (declassification is NOT here)
  policy.yaml    TRUSTED policy: principals, roles, recipients, document classifications
  policy.py      loads + versions the policy
  store.py       SQLite: artifacts+labels, workflows, audit, mock outbox
  tools.py       the 3 raw tools: read_document, save_report, deliver_inbox (no policy logic)
  gate.py        validate -> evaluate -> AUDIT -> execute -> persist
  llm.py         NaiveAgent (attack simulator) + LLMProposer (plug any LLM; it can only propose)
  scenarios.py   live demo scenarios (used by the dashboard and the tests)
app.py           Streamlit dashboard
tests/           pytest suite
data/docs/       sample documents (one contains a prompt injection)
```

## Design in one minute

* **Labels** = sensitivity (PUBLIC < INTERNAL < CONFIDENTIAL < SECRET) + integrity (TRUSTED / UNTRUSTED) + provenance.
* **Derived artifacts** (summaries, reports) get `join(labels of everything the workflow has read + declared parents)`.
  Declaring `parents=[]` cannot lower a label: workflow taint is stored in SQLite and survives restarts.
* **Delivery** needs: role permits it, principal cleared for the artifact, recipient on the authorized list,
  `artifact.sensitivity <= recipient.clearance`, and no untrusted content to external recipients.
* **Delivery tool takes an artifact id, not free text**, so the proposer cannot smuggle other content out.
* **Declassification** only via the `operator` channel (set by the app, never by the proposal), by a role that
  holds the `declassify` permission, with a mandatory reason. It is audited.
* **Audit** row is written *before* execution and updated after; every row lists the checks that were evaluated.
* **Proposals** reject unknown fields, so an LLM cannot attach its own label, role or clearance.
* **Identity** (`principal`, `workflow_id`) is injected by the system for LLM output, not taken from the model.

## Demo order (about 4 minutes)

1. *Authorized report* → everything allowed, one mail in the mock inbox.
2. *Leak attempt* → delivery to the external partner is BLOCKED (open "Why?").
3. *Injected document* → the naive agent obeys the hidden instruction; the gateway blocks the exfiltration.
4. *Laundering attempt* → SECRET survives summarization; only the SECRET inbox accepts it.
5. *Declassification* → agent blocked, analyst blocked, admin operator allowed, audited.
6. **Restart** button → new Gate + new SQLite connection; the restriction still holds.
7. `pytest` → blocked calls = 0 tool executions.

All of this is executed **live**. There is no prerecorded replay in this project.

## Plugging in a real LLM (optional)

```python
from agentgate.llm import LLMProposer
proposer = LLMProposer(complete=lambda prompt: my_llm_call(prompt))   # any provider
proposals, errors = proposer.propose("summarize q3 and send to internal", "bob", "wf-1")
for p in proposals:
    result = gate.submit(p)          # the gate still has the only say
```

## Known limitations (be upfront with judges)

* Labels track what flowed **through the gateway**. Information the model already memorized, or copied by
  a human, is outside this model.
* Workflow taint is conservative: reading a SECRET document taints every later report in that workflow.
* Prototype auth: the principal and the `operator` channel are set by the calling app; a real deployment
  would bind them to authenticated sessions.
* No semantic content scanning: this is about information **flow**, not classifying text as harmful.

## Related work / credits

Ideas draw on CaMeL (capability-based IFC for LLM agents, Google DeepMind / ETH),
Microsoft FIDES (integrity + confidentiality labels), and the open-source
[agent-policy-gateway](https://pypi.org/project/agent-policy-gateway/) (Apache-2.0).
This repository's gateway is independent code and does not depend on those projects.
