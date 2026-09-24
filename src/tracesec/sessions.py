"""
tracesec.sessions

Manages the set of identities (authenticated users, an optional admin,
and the unauthenticated/anonymous context) that TRACE sends requests
as. At least two USER-role identities are required, since the BOLA and
excessive-exposure oracles need a genuine "someone else" to run their
differential checks (does user B get user A's resource?).
"""

from dataclasses import dataclass, field
from enum import StrEnum


class Role(StrEnum):
    USER = "user"
    ADMIN = "admin"
    ANONYMOUS = "anonymous"


@dataclass(frozen=True)
class Identity:
    """One identity TRACE can send requests as: a label, a role, and
    the headers that authenticate as that identity on the target."""

    label: str
    role: Role
    headers: dict[str, str] = field(default_factory=dict)


class SessionManager:
    """Holds a named set of Identities for one target. Requires at
    least two Role.USER identities at construction time.
    """

    def __init__(self, identities: list[Identity]) -> None:
        user_identities = [i for i in identities if i.role == Role.USER]
        if len(user_identities) < 2:
            raise ValueError(
                "SessionManager requires at least two Role.USER identities "
                "to run cross-user (BOLA-style) checks"
            )
        self._identities: dict[str, Identity] = {i.label: i for i in identities}
        self._users = user_identities

    def get(self, label: str) -> Identity:
        try:
            return self._identities[label]
        except KeyError as exc:
            raise KeyError(f"no identity registered with label {label!r}") from exc

    @property
    def users(self) -> list[Identity]:
        return list(self._users)

    def other_user(self, than: str) -> Identity:
        """Return a USER identity whose label is not `than` -- the
        'someone else' needed for a BOLA cross-access check."""
        for identity in self._users:
            if identity.label != than:
                return identity
        raise ValueError(f"no other user identity distinct from {than!r}")

    @property
    def admin(self) -> Identity | None:
        for identity in self._identities.values():
            if identity.role == Role.ADMIN:
                return identity
        return None

    @property
    def anonymous(self) -> Identity:
        return Identity(label="anonymous", role=Role.ANONYMOUS, headers={})
