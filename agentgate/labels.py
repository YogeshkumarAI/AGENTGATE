"""Label algebra: join, flow check.

Declassification is deliberately NOT here. It lives in the gate, behind the
operator channel + role check, so no tool or proposer can call it.
"""
from typing import Iterable

from .models import Integrity, Label, Sensitivity


def join(labels: Iterable[Label]) -> Label:
    """Least upper bound: highest sensitivity, lowest integrity, union of provenance."""
    labels = list(labels)
    if not labels:
        return Label(sensitivity=Sensitivity.PUBLIC, integrity=Integrity.TRUSTED, provenance=())
    return Label(
        sensitivity=max(l.sensitivity for l in labels),
        integrity=min(l.integrity for l in labels),
        provenance=tuple(sorted({p for l in labels for p in l.provenance})),
    )


def derive(labels: Iterable[Label], extra_provenance: Iterable[str] = ()) -> Label:
    """Label for an artifact derived from the given inputs (summary, report, ...)."""
    joined = join(labels)
    prov = tuple(sorted(set(joined.provenance) | set(extra_provenance)))
    return Label(sensitivity=joined.sensitivity, integrity=joined.integrity, provenance=prov)


def can_flow_to(label: Label, clearance: Sensitivity) -> bool:
    """Information may flow to a reader only if the reader's clearance dominates it."""
    return label.sensitivity <= clearance
