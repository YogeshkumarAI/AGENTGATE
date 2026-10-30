"""SQLite persistence: artifacts + labels, workflow state, outbox, audit log."""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .models import Label

SCHEMA = """
CREATE TABLE IF NOT EXISTS artifacts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL, name TEXT NOT NULL, content TEXT NOT NULL,
    sensitivity INTEGER NOT NULL, integrity INTEGER NOT NULL, provenance TEXT NOT NULL,
    workflow_id TEXT, created_by TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS workflows(
    id TEXT PRIMARY KEY, principal TEXT NOT NULL, created_at TEXT
);
CREATE TABLE IF NOT EXISTS workflow_reads(
    workflow_id TEXT NOT NULL, artifact_id INTEGER NOT NULL,
    PRIMARY KEY(workflow_id, artifact_id)
);
CREATE TABLE IF NOT EXISTS audit(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT, workflow_id TEXT, principal TEXT, channel TEXT,
    operation TEXT, resource TEXT, recipient TEXT,
    proposal TEXT, allowed INTEGER, rule TEXT, reason TEXT, checks TEXT,
    input_label TEXT, output_label TEXT, policy_version TEXT,
    executed INTEGER DEFAULT 0, result TEXT, artifact_id INTEGER
);
CREATE TABLE IF NOT EXISTS outbox(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT, recipient TEXT, subject TEXT, body TEXT, artifact_id INTEGER
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    def reset(self):
        for table in ("artifacts", "workflows", "workflow_reads", "audit", "outbox"):
            self.conn.execute(f"DELETE FROM {table}")
        self.conn.execute("DELETE FROM sqlite_sequence")
        self.conn.commit()

    # ------------------------------------------------------------ artifacts --
    @staticmethod
    def _artifact(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["label"] = Label(
            sensitivity=d.pop("sensitivity"),
            integrity=d.pop("integrity"),
            provenance=tuple(json.loads(d.pop("provenance"))),
        )
        return d

    def add_artifact(self, kind, name, content, label: Label, workflow_id, created_by) -> int:
        cur = self.conn.execute(
            "INSERT INTO artifacts(kind,name,content,sensitivity,integrity,provenance,"
            "workflow_id,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (kind, name, content, int(label.sensitivity), int(label.integrity),
             json.dumps(list(label.provenance)), workflow_id, created_by, _now()),
        )
        self.conn.commit()
        return cur.lastrowid

    def find_artifact(self, kind, name, content, label: Label) -> Optional[int]:
        row = self.conn.execute(
            "SELECT id FROM artifacts WHERE kind=? AND name=? AND content=? "
            "AND sensitivity=? AND integrity=? ORDER BY id DESC LIMIT 1",
            (kind, name, content, int(label.sensitivity), int(label.integrity)),
        ).fetchone()
        return row["id"] if row else None

    def get_artifact(self, artifact_id: int) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
        return self._artifact(row) if row else None

    def resolve(self, ref) -> Optional[dict]:
        """Resolve an artifact by numeric id or by name (latest wins)."""
        ref = str(ref).strip()
        if ref.isdigit():
            return self.get_artifact(int(ref))
        row = self.conn.execute(
            "SELECT * FROM artifacts WHERE name=? ORDER BY id DESC LIMIT 1", (ref,)
        ).fetchone()
        return self._artifact(row) if row else None

    def set_label(self, artifact_id: int, label: Label):
        self.conn.execute(
            "UPDATE artifacts SET sensitivity=?, integrity=?, provenance=? WHERE id=?",
            (int(label.sensitivity), int(label.integrity),
             json.dumps(list(label.provenance)), artifact_id),
        )
        self.conn.commit()

    def list_artifacts(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM artifacts ORDER BY id").fetchall()
        return [self._artifact(r) for r in rows]

    # ------------------------------------------------------------ workflows --
    def get_workflow(self, workflow_id) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM workflows WHERE id=?", (workflow_id,)).fetchone()
        return dict(row) if row else None

    def create_workflow(self, workflow_id, principal):
        self.conn.execute(
            "INSERT OR IGNORE INTO workflows(id,principal,created_at) VALUES(?,?,?)",
            (workflow_id, principal, _now()),
        )
        self.conn.commit()

    def add_read(self, workflow_id, artifact_id):
        self.conn.execute(
            "INSERT OR IGNORE INTO workflow_reads(workflow_id,artifact_id) VALUES(?,?)",
            (workflow_id, artifact_id),
        )
        self.conn.commit()

    def workflow_labels(self, workflow_id) -> list[Label]:
        rows = self.conn.execute(
            "SELECT a.* FROM artifacts a JOIN workflow_reads r ON a.id=r.artifact_id "
            "WHERE r.workflow_id=?", (workflow_id,),
        ).fetchall()
        return [self._artifact(r)["label"] for r in rows]

    # --------------------------------------------------------------- outbox --
    def add_outbox(self, recipient, subject, body, artifact_id) -> int:
        cur = self.conn.execute(
            "INSERT INTO outbox(ts,recipient,subject,body,artifact_id) VALUES(?,?,?,?,?)",
            (_now(), recipient, subject, body, artifact_id),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_outbox(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM outbox ORDER BY id")]

    # ---------------------------------------------------------------- audit --
    def add_audit(self, **f) -> int:
        cur = self.conn.execute(
            "INSERT INTO audit(ts,workflow_id,principal,channel,operation,resource,recipient,"
            "proposal,allowed,rule,reason,checks,input_label,output_label,policy_version,"
            "executed,result,artifact_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,NULL,NULL)",
            (_now(), f.get("workflow_id"), f.get("principal"), f.get("channel"),
             f.get("operation"), f.get("resource"), f.get("recipient"),
             json.dumps(f.get("proposal"), default=str), int(f["allowed"]), f["rule"], f["reason"],
             json.dumps(f.get("checks", [])), json.dumps(f.get("input_label")),
             json.dumps(f.get("output_label")), f.get("policy_version")),
        )
        self.conn.commit()
        return cur.lastrowid

    def finish_audit(self, audit_id, executed: bool, result: str, artifact_id=None):
        self.conn.execute(
            "UPDATE audit SET executed=?, result=?, artifact_id=? WHERE id=?",
            (int(executed), result, artifact_id, audit_id),
        )
        self.conn.commit()

    def list_audit(self) -> list[dict]:
        out = []
        for r in self.conn.execute("SELECT * FROM audit ORDER BY id"):
            d = dict(r)
            for key in ("proposal", "checks", "input_label", "output_label"):
                d[key] = json.loads(d[key]) if d[key] else None
            d["allowed"] = bool(d["allowed"])
            d["executed"] = bool(d["executed"])
            out.append(d)
        return out
