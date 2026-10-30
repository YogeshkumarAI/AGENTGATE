"""AGENTGATE: the independent policy gateway.

Pipeline for every proposal (the LLM never takes part in any step):
  1. validate   - Pydantic schema; unknown fields (e.g. a self-asserted label) are rejected
  2. evaluate   - trusted policy + labels loaded from SQLite (never from the proposal)
  3. audit      - the decision is written BEFORE anything executes
  4. execute    - only if allowed; the raw tool is not called at all otherwise
  5. persist    - derived artifact gets a label computed by the gate, stored in SQLite
"""
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from pydantic import ValidationError

from .labels import derive
from .models import ActionProposal, Check, Decision, Integrity, Label
from .store import Store
from .tools import build_tools

REPORT_NAME = re.compile(r"[A-Za-z0-9_.\-]{1,64}")


@dataclass
class GateResult:
    decision: Decision
    output: Any = None
    artifact_id: Optional[int] = None
    audit_id: Optional[int] = None
    executed: bool = False
    error: Optional[str] = None
    proposal: Optional[ActionProposal] = None

    @property
    def allowed(self) -> bool:
        return self.decision.allowed


class Gate:
    def __init__(self, store: Store, policy, docs_dir, tools: Optional[dict] = None):
        self.store = store
        self.policy = policy
        self.docs_dir = Path(docs_dir)
        self.tools = tools if tools is not None else build_tools(store, self.docs_dir)

    # ----------------------------------------------------------------- API --
    def submit(self, proposal, channel: str = "agent") -> GateResult:
        """Evaluate and (if allowed) execute one proposed action.

        `channel` is set by the calling application, never by the proposal:
        "agent" for anything an LLM produced, "operator" for an authenticated human/process.
        """
        channel = channel if channel in ("agent", "operator") else "agent"
        raw = proposal if isinstance(proposal, dict) else proposal.model_dump(mode="json")

        try:
            p = ActionProposal.model_validate(raw)
        except ValidationError as e:
            errs = "; ".join(f"{'.'.join(map(str, x['loc'])) or 'proposal'}: {x['msg']}" for x in e.errors())
            decision = Decision(
                allowed=False, rule="schema_validation", reason=f"malformed proposal rejected ({errs})",
                checks=[Check(name="schema_valid", passed=False, detail=errs)],
            )
            audit_id = self._audit(raw, channel, decision, fallback=True)
            self.store.finish_audit(audit_id, False, "blocked: not executed")
            return GateResult(decision=decision, audit_id=audit_id)

        decision = self._evaluate(p, channel)
        audit_id = self._audit(p.model_dump(mode="json"), channel, decision)  # BEFORE execution
        result = GateResult(decision=decision, audit_id=audit_id, proposal=p)

        if not decision.allowed:
            self.store.finish_audit(audit_id, False, "blocked: tool not executed")
            return result

        try:
            output, artifact_id = self._execute(p, decision)
            result.output, result.artifact_id, result.executed = output, artifact_id, True
            self.store.finish_audit(audit_id, True, f"ok: {self._summarise(p, artifact_id)}", artifact_id)
        except Exception as e:  # tool failure is recorded, never swallowed silently
            result.error = f"{type(e).__name__}: {e}"
            self.store.finish_audit(audit_id, True, f"tool error: {result.error}")
        return result

    # ------------------------------------------------------------ evaluate --
    def _evaluate(self, p: ActionProposal, channel: str) -> Decision:
        policy, store = self.policy, self.store
        checks: list[Check] = []

        def ok(name: str, passed: bool, detail: str) -> bool:
            checks.append(Check(name=name, passed=passed, detail=detail))
            return passed

        def deny(rule: str, reason: str, label: Optional[Label] = None) -> Decision:
            return Decision(allowed=False, rule=rule, reason=reason, checks=checks, input_label=label)

        def allow(rule: str, reason: str, inp: Optional[Label], out: Optional[Label]) -> Decision:
            return Decision(allowed=True, rule=rule, reason=reason, checks=checks,
                            input_label=inp, output_label=out)

        # --- identity ---------------------------------------------------------
        role_name = policy.principals.get(p.principal)
        if not ok("known_principal", role_name is not None,
                  f"'{p.principal}' -> role '{role_name}'" if role_name else f"'{p.principal}' is not registered"):
            return deny("unknown_principal", f"principal '{p.principal}' is not registered")
        role = policy.roles[role_name]

        wf = store.get_workflow(p.workflow_id)
        if wf is not None:
            if not ok("workflow_owner", wf["principal"] == p.principal,
                      f"workflow '{p.workflow_id}' belongs to '{wf['principal']}'"):
                return deny("workflow_owner", f"workflow '{p.workflow_id}' belongs to another principal")
        else:
            ok("workflow_owner", True, f"new workflow '{p.workflow_id}' will be bound to '{p.principal}'")

        if not ok("role_allows_operation", p.operation in role.operations,
                  f"role '{role_name}' operations: {', '.join(role.operations)}"):
            return deny("role_not_permitted", f"role '{role_name}' may not perform '{p.operation}'")

        # --- read_document ----------------------------------------------------
        if p.operation == "read_document":
            spec = policy.documents.get(p.resource)
            if not ok("document_registered", spec is not None,
                      f"'{p.resource}' in classification registry" if spec else f"'{p.resource}' is not registered"):
                return deny("document_not_registered", f"document '{p.resource}' is not in the registry")
            label = Label(sensitivity=spec.sensitivity, integrity=spec.integrity,
                          provenance=(f"doc:{p.resource}",))
            if not ok("reader_clearance", label.sensitivity <= role.max_read,
                      f"document is {label.sensitivity.name}; role '{role_name}' may read up to {role.max_read.name}"):
                return deny("insufficient_clearance",
                            f"{label.sensitivity.name} document exceeds {role.max_read.name} clearance of '{role_name}'",
                            label)
            return allow("allow_read", f"read of {label.describe()} document permitted", label, label)

        # --- save_report ------------------------------------------------------
        if p.operation == "save_report":
            if not ok("report_name_valid", bool(REPORT_NAME.fullmatch(p.resource)),
                      "name must match [A-Za-z0-9_.-]{1,64}"):
                return deny("invalid_report_name", "report name contains illegal characters")
            if not ok("content_present", bool(p.content and p.content.strip()), "report content is required"):
                return deny("missing_content", "report content is empty")
            parents = []
            for ref in p.parents:
                art = store.resolve(ref)
                if not ok("parent_exists", art is not None, f"parent '{ref}' found" if art else f"parent '{ref}' not found"):
                    return deny("unknown_parent", f"declared parent '{ref}' does not exist")
                if not ok("parent_readable", art["label"].sensitivity <= role.max_read,
                          f"parent '{ref}' is {art['label'].sensitivity.name}; clearance {role.max_read.name}"):
                    return deny("insufficient_clearance", f"principal may not use parent '{ref}'", art["label"])
                parents.append(art)
            wf_labels = store.workflow_labels(p.workflow_id)
            label = derive([a["label"] for a in parents] + wf_labels,
                           extra_provenance=[f"art:{a['id']}" for a in parents])
            ok("label_derived", True,
               f"join of {len(parents)} declared parent(s) + {len(wf_labels)} item(s) already read in this workflow "
               f"= {label.describe()} (declared parents cannot lower it)")
            return allow("allow_save", f"report saved with derived label {label.describe()}", label, label)

        # --- deliver_inbox ----------------------------------------------------
        if p.operation == "deliver_inbox":
            art = store.resolve(p.resource)
            if not ok("artifact_exists", art is not None,
                      f"artifact '{p.resource}' found" if art else f"artifact '{p.resource}' not found"):
                return deny("unknown_artifact", f"artifact '{p.resource}' does not exist")
            label = art["label"]
            if not ok("reader_clearance", label.sensitivity <= role.max_read,
                      f"artifact is {label.sensitivity.name}; role '{role_name}' clearance {role.max_read.name}"):
                return deny("insufficient_clearance", "principal may not handle this artifact", label)
            if not ok("recipient_provided", bool(p.recipient), "a recipient is required"):
                return deny("missing_recipient", "no recipient given", label)
            rec = policy.recipients.get(p.recipient)
            if not ok("recipient_authorized", rec is not None,
                      f"'{p.recipient}' on recipient list" if rec else f"'{p.recipient}' is NOT on the authorized recipient list"):
                return deny("recipient_not_authorized", f"recipient '{p.recipient}' is not authorized", label)
            if not ok("information_flow", label.sensitivity <= rec.clearance,
                      f"artifact {label.sensitivity.name} -> recipient clearance {rec.clearance.name}"):
                return deny("information_flow_violation",
                            f"{label.sensitivity.name} information may not flow to a {rec.clearance.name}-cleared recipient",
                            label)
            if not ok("untrusted_to_external", not (label.integrity == Integrity.UNTRUSTED and rec.external),
                      f"artifact integrity {label.integrity.name}; recipient external={rec.external}"):
                return deny("untrusted_to_external",
                            "untrusted-integrity content may not be sent to an external recipient", label)
            return allow("allow_delivery", f"delivery of {label.describe()} artifact to '{p.recipient}' permitted",
                         label, label)

        # --- declassify -------------------------------------------------------
        if p.operation == "declassify":
            if not ok("operator_channel", channel == "operator",
                      f"request arrived on channel '{channel}'; declassification needs the operator channel"):
                return deny("declassify_requires_operator",
                            "only an authorized operator process may change a classification, not the agent")
            if not ok("reason_present", bool(p.reason and p.reason.strip()), "a justification is mandatory"):
                return deny("declassify_requires_reason", "declassification needs a written reason")
            if not ok("new_level_given", p.new_sensitivity is not None, "target sensitivity required"):
                return deny("missing_target_level", "no target sensitivity given")
            art = store.resolve(p.resource)
            if not ok("artifact_exists", art is not None,
                      f"artifact '{p.resource}' found" if art else f"artifact '{p.resource}' not found"):
                return deny("unknown_artifact", f"artifact '{p.resource}' does not exist")
            old = art["label"]
            new = Label(sensitivity=p.new_sensitivity, integrity=old.integrity,
                        provenance=tuple(sorted(set(old.provenance) | {f"declassified-by:{p.principal}"})))
            return allow("allow_declassify",
                         f"{old.sensitivity.name} -> {new.sensitivity.name} by '{p.principal}': {p.reason}", old, new)

        return deny("unknown_operation", f"operation '{p.operation}' is not supported")

    # ------------------------------------------------------------- execute --
    def _execute(self, p: ActionProposal, d: Decision):
        store = self.store
        if store.get_workflow(p.workflow_id) is None:
            store.create_workflow(p.workflow_id, p.principal)

        if p.operation == "read_document":
            content = self.tools["read_document"](name=p.resource)
            art_id = store.find_artifact("document", p.resource, content, d.output_label)
            if art_id is None:
                art_id = store.add_artifact("document", p.resource, content, d.output_label,
                                            p.workflow_id, p.principal)
            store.add_read(p.workflow_id, art_id)  # workflow taint persists in SQLite
            return content, art_id

        if p.operation == "save_report":
            art_id = self.tools["save_report"](name=p.resource, content=p.content, label=d.output_label,
                                               workflow_id=p.workflow_id, created_by=p.principal)
            for ref in p.parents:
                parent = store.resolve(ref)
                store.add_read(p.workflow_id, parent["id"])
            return {"artifact_id": art_id, "label": d.output_label.public()}, art_id

        if p.operation == "deliver_inbox":
            art = store.resolve(p.resource)
            outbox_id = self.tools["deliver_inbox"](recipient=p.recipient, artifact_id=art["id"],
                                                    subject=f"[AGENTGATE] {art['name']}")
            return {"outbox_id": outbox_id}, art["id"]

        if p.operation == "declassify":
            art = store.resolve(p.resource)
            store.set_label(art["id"], d.output_label)
            return {"artifact_id": art["id"], "label": d.output_label.public()}, art["id"]

        raise ValueError(f"unsupported operation {p.operation}")

    # --------------------------------------------------------------- audit --
    def _audit(self, raw: dict, channel: str, d: Decision, fallback: bool = False) -> int:
        safe = dict(raw)
        if isinstance(safe.get("content"), str) and len(safe["content"]) > 500:
            safe["content"] = safe["content"][:500] + "...[truncated]"
        return self.store.add_audit(
            workflow_id=str(raw.get("workflow_id")) if raw.get("workflow_id") is not None else None,
            principal=str(raw.get("principal")) if raw.get("principal") is not None else None,
            channel=channel,
            operation=str(raw.get("operation")) if raw.get("operation") is not None else None,
            resource=str(raw.get("resource")) if raw.get("resource") is not None else None,
            recipient=raw.get("recipient") if isinstance(raw.get("recipient"), str) else None,
            proposal=safe, allowed=d.allowed, rule=d.rule, reason=d.reason,
            checks=[c.model_dump() for c in d.checks],
            input_label=d.input_label.public() if d.input_label else None,
            output_label=d.output_label.public() if d.output_label else None,
            policy_version=self.policy.version,
        )

    @staticmethod
    def _summarise(p: ActionProposal, artifact_id) -> str:
        return f"{p.operation} on '{p.resource}'" + (f" (artifact {artifact_id})" if artifact_id else "")
