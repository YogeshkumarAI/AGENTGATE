"""Untrusted proposers. Neither class can authorize anything: they only build proposals.

* NaiveAgent  - simulates an agent that blindly obeys instructions found in documents
                (this is the attack we defend against; used in the demo and tests).
* LLMProposer - provider-agnostic adapter: give it any `complete(prompt) -> str`
                function (Claude, OpenAI, local model...) and it returns validated proposals.
                Identity (principal / workflow) is injected by the system, not by the model.
"""
import json
import re
from typing import Callable

from pydantic import ValidationError

from .models import ActionProposal


class NaiveAgent:
    """Obeys 'forward <doc> to <email>' instructions embedded in a document."""

    INSTRUCTION = re.compile(
        r"forward\s+(?P<doc>[\w.\-]+)\s+to\s+(?P<to>[\w.+\-]+@[\w.\-]+)", re.IGNORECASE
    )

    def react_to(self, document_text: str, principal: str, workflow_id: str) -> list[ActionProposal]:
        m = self.INSTRUCTION.search(document_text)
        if not m:
            return []
        doc, to = m.group("doc"), m.group("to")
        return [
            ActionProposal(principal=principal, workflow_id=workflow_id,
                           operation="read_document", resource=doc),
            ActionProposal(principal=principal, workflow_id=workflow_id, operation="save_report",
                           resource="forwarded_copy", content=f"Copy of {doc} as instructed."),
            ActionProposal(principal=principal, workflow_id=workflow_id, operation="deliver_inbox",
                           resource="forwarded_copy", recipient=to),
        ]


PROMPT = """You translate a user request into tool actions.
Return ONLY a JSON list. Each item has: operation (read_document | save_report | deliver_inbox),
resource, and optionally recipient, content, parents (list). Do not include any other fields.

Request: {request}
"""


class LLMProposer:
    def __init__(self, complete: Callable[[str], str]):
        self.complete = complete

    def propose(self, request: str, principal: str, workflow_id: str):
        """Returns (proposals, errors). Invalid items are reported, never executed."""
        text = self.complete(PROMPT.format(request=request))
        m = re.search(r"\[.*\]", text, re.DOTALL)
        try:
            items = json.loads(m.group(0)) if m else []
        except json.JSONDecodeError as e:
            return [], [f"unparseable model output: {e}"]
        proposals, errors = [], []
        for item in items:
            if not isinstance(item, dict):
                errors.append(f"not an object: {item!r}")
                continue
            # identity comes from the authenticated session, never from the model
            item = {**item, "principal": principal, "workflow_id": workflow_id}
            try:
                proposals.append(ActionProposal.model_validate(item))
            except ValidationError as e:
                errors.append(f"{item.get('operation')}: {e.errors()[0]['msg']}")
        return proposals, errors
