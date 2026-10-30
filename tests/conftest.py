import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentgate import ActionProposal, Gate, Store, build_tools, load_policy  # noqa: E402

DOCS = ROOT / "data" / "docs"


def make_env(db_path):
    """Gate wired to spy tools so tests can prove blocked calls never reach a tool."""
    store = Store(db_path)
    policy = load_policy()
    calls = Counter()

    def spy(name, fn):
        def wrapper(**kw):
            calls[name] += 1
            return fn(**kw)
        return wrapper

    tools = {k: spy(k, v) for k, v in build_tools(store, DOCS).items()}
    gate = Gate(store, policy, DOCS, tools=tools)
    return SimpleNamespace(store=store, policy=policy, gate=gate, calls=calls,
                           db=db_path, tools=tools)


@pytest.fixture
def env(tmp_path):
    return make_env(tmp_path / "test.db")


def reopen(env):
    """Simulate a process restart: brand-new Store connection and Gate on the same file."""
    env.store.close()
    return make_env(env.db)


def P(**kw) -> ActionProposal:
    kw.setdefault("principal", "bob")
    kw.setdefault("workflow_id", "wf-test")
    return ActionProposal(**kw)


def read(env, doc, **kw):
    return env.gate.submit(P(operation="read_document", resource=doc, **kw))


def save(env, name, content="summary text", **kw):
    return env.gate.submit(P(operation="save_report", resource=name, content=content, **kw))


def deliver(env, resource, recipient, **kw):
    return env.gate.submit(P(operation="deliver_inbox", resource=resource, recipient=recipient, **kw))
