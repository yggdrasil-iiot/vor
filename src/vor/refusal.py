"""The closed set of refusal reasons, in the order the checks run. The first failing check decides the reason."""

from __future__ import annotations

import hashlib
from typing import Any

REASONS = (
    "head-unverified",
    "head-rollback",
    "head-expired",
    "provenance-mismatch",
    "binding-invalid",
    "meaning-retired",
    "unit-unknown",
    "policy-missing",
    "no-sample",
    "sample-unknown",
    "bad-quality",
    "uncertain-rejected",
    "stale",
    "future-sample",
    "skew-exceeded",
    "location-mismatch",
)

DIGEST_RULE = "raw-bytes-sha256"


class Refusal(Exception):
    """A failed check: one reason from REASONS and the evidence that shows why. Never carries a sample value."""

    def __init__(self, reason: str, **evidence: Any):
        if reason not in REASONS:
            raise ValueError(f"not a refusal reason: {reason}")
        super().__init__(reason)
        self.reason = reason
        self.evidence = evidence

    def payload(self) -> dict:
        return {"answer": None, "verdict": {"usable": False, "reason": self.reason, "evidence": self.evidence}}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
