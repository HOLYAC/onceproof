"""Typed service errors carry the state an HTTP caller can act on."""

from __future__ import annotations


class RateLimitError(RuntimeError):
    """Report the bounded wait without exposing credential or proof state."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("rate_limited")
        self.retry_after_seconds = retry_after_seconds


class StoreCorruptionError(RuntimeError):
    """Fail closed when durable state cannot satisfy its persisted invariants."""

    def __init__(self) -> None:
        super().__init__("store_corrupt")


class KeyringCommitUncertain(RuntimeError):
    """Report that replacement reached the filesystem but directory sync failed."""

    def __init__(self) -> None:
        super().__init__("keyring_commit_uncertain")


class RestoreRequiredError(RuntimeError):
    """Refuse a recovery snapshot until old authority is invalidated."""

    def __init__(self) -> None:
        super().__init__("restore_activation_required")


__all__ = [
    "KeyringCommitUncertain",
    "RateLimitError",
    "RestoreRequiredError",
    "StoreCorruptionError",
]
