"""Load the trusted policy from YAML."""
import hashlib
from pathlib import Path

import yaml

from .models import Policy

DEFAULT_POLICY_PATH = Path(__file__).with_name("policy.yaml")


def load_policy(path=DEFAULT_POLICY_PATH) -> Policy:
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    policy = Policy.model_validate(data)
    policy.version = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return policy
