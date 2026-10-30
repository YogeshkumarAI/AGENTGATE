"""Pydantic models: security labels, action proposals, decisions and policy structure.

Everything that crosses a trust boundary (LLM output, document text, UI input)
is validated here before the gate looks at it.
"""
from enum import IntEnum
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Sensitivity(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3


class Integrity(IntEnum):
    UNTRUSTED = 0
    TRUSTED = 1


def _parse_enum(enum_cls, value):
    """Accept enum members, ints, or case-insensitive names."""
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        try:
            return enum_cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown {enum_cls.__name__}: {value!r}")
    return value


Operation = Literal["read_document", "save_report", "deliver_inbox", "declassify"]
Channel = Literal["agent", "operator"]


class Label(BaseModel):
    """Security label that travels with every artifact."""

    model_config = ConfigDict(frozen=True)

    sensitivity: Sensitivity
    integrity: Integrity
    provenance: tuple[str, ...] = ()

    @field_validator("sensitivity", mode="before")
    @classmethod
    def _s(cls, v):
        return _parse_enum(Sensitivity, v)

    @field_validator("integrity", mode="before")
    @classmethod
    def _i(cls, v):
        return _parse_enum(Integrity, v)

    def describe(self) -> str:
        return f"{self.sensitivity.name}/{self.integrity.name}"

    def public(self) -> dict[str, Any]:
        return {
            "sensitivity": self.sensitivity.name,
            "integrity": self.integrity.name,
            "provenance": list(self.provenance),
        }


class ActionProposal(BaseModel):
    """What an untrusted proposer (LLM / agent) may ask for.

    `extra="forbid"` means a proposal cannot smuggle in its own label,
    clearance or role: unknown fields are rejected outright.
    """

    model_config = ConfigDict(extra="forbid")

    principal: str = Field(min_length=1, max_length=64)
    workflow_id: str = Field(min_length=1, max_length=64)
    operation: Operation
    resource: str = Field(min_length=1, max_length=256)
    recipient: Optional[str] = Field(default=None, max_length=256)
    content: Optional[str] = Field(default=None, max_length=20000)
    parents: list[str] = Field(default_factory=list, max_length=20)
    new_sensitivity: Optional[Sensitivity] = None
    reason: Optional[str] = Field(default=None, max_length=500)

    @field_validator("new_sensitivity", mode="before")
    @classmethod
    def _ns(cls, v):
        return _parse_enum(Sensitivity, v) if v is not None else v


class Check(BaseModel):
    name: str
    passed: bool
    detail: str


class Decision(BaseModel):
    allowed: bool
    rule: str
    reason: str
    checks: list[Check] = Field(default_factory=list)
    input_label: Optional[Label] = None
    output_label: Optional[Label] = None


# ---------------------------------------------------------------- policy ----
class RoleSpec(BaseModel):
    operations: list[Operation]
    max_read: Sensitivity

    @field_validator("max_read", mode="before")
    @classmethod
    def _m(cls, v):
        return _parse_enum(Sensitivity, v)


class RecipientSpec(BaseModel):
    clearance: Sensitivity
    external: bool = False

    @field_validator("clearance", mode="before")
    @classmethod
    def _c(cls, v):
        return _parse_enum(Sensitivity, v)


class DocSpec(BaseModel):
    sensitivity: Sensitivity
    integrity: Integrity

    @field_validator("sensitivity", mode="before")
    @classmethod
    def _s(cls, v):
        return _parse_enum(Sensitivity, v)

    @field_validator("integrity", mode="before")
    @classmethod
    def _i(cls, v):
        return _parse_enum(Integrity, v)


class Policy(BaseModel):
    """Trusted policy. Loaded from policy.yaml, never from documents or the LLM."""

    principals: dict[str, str]
    roles: dict[str, RoleSpec]
    recipients: dict[str, RecipientSpec]
    documents: dict[str, DocSpec]
    version: str = ""

    @model_validator(mode="after")
    def _roles_exist(self):
        for who, role in self.principals.items():
            if role not in self.roles:
                raise ValueError(f"principal '{who}' has unknown role '{role}'")
        return self
