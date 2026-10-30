"""The three raw tools. They do their job and NOTHING else: no policy logic here.

They are only ever reached through Gate.submit(); nothing else exposes them.
Note that deliver_inbox takes an artifact id, not free text: it delivers exactly
the stored, labelled artifact, so the proposer cannot smuggle other content out.
"""
from pathlib import Path

from .models import Label
from .store import Store


def build_tools(store: Store, docs_dir) -> dict:
    docs_dir = Path(docs_dir)

    def read_document(name: str) -> str:
        if Path(name).name != name:  # defence in depth against path tricks
            raise ValueError("invalid document name")
        return (docs_dir / name).read_text(encoding="utf-8")

    def save_report(name: str, content: str, label: Label, workflow_id: str, created_by: str) -> int:
        return store.add_artifact("report", name, content, label, workflow_id, created_by)

    def deliver_inbox(recipient: str, artifact_id: int, subject: str) -> int:
        artifact = store.get_artifact(artifact_id)
        return store.add_outbox(recipient, subject, artifact["content"], artifact_id)

    return {
        "read_document": read_document,
        "save_report": save_report,
        "deliver_inbox": deliver_inbox,
    }
