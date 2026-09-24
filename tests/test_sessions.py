"""
Unit tests for tracesec.sessions: identity/role manager for a target.
"""

import pytest

from tracesec.sessions import Identity, Role, SessionManager


def _users():
    return [
        Identity(label="user-a", role=Role.USER, headers={"X-User-Id": "1"}),
        Identity(label="user-b", role=Role.USER, headers={"X-User-Id": "2"}),
    ]


def test_requires_at_least_two_users():
    with pytest.raises(ValueError, match="at least two"):
        SessionManager([Identity(label="solo", role=Role.USER, headers={})])


def test_requires_at_least_two_users_even_with_admin_present():
    identities = [
        Identity(label="user-a", role=Role.USER, headers={}),
        Identity(label="admin", role=Role.ADMIN, headers={}),
    ]
    with pytest.raises(ValueError, match="at least two"):
        SessionManager(identities)


def test_get_returns_identity_by_label():
    manager = SessionManager(_users())
    identity = manager.get("user-a")
    assert identity.label == "user-a"
    assert identity.headers == {"X-User-Id": "1"}


def test_get_unknown_label_raises_keyerror():
    manager = SessionManager(_users())
    with pytest.raises(KeyError):
        manager.get("nobody")


def test_other_user_returns_a_different_user():
    manager = SessionManager(_users())
    other = manager.other_user(than="user-a")
    assert other.label == "user-b"


def test_admin_returns_none_when_absent():
    manager = SessionManager(_users())
    assert manager.admin is None


def test_admin_returns_admin_identity_when_present():
    identities = [
        *_users(),
        Identity(label="root", role=Role.ADMIN, headers={"X-User-Id": "0"}),
    ]
    manager = SessionManager(identities)
    admin = manager.admin
    assert admin is not None
    assert admin.label == "root"


def test_anonymous_has_no_headers():
    manager = SessionManager(_users())
    assert manager.anonymous.headers == {}
    assert manager.anonymous.role == Role.ANONYMOUS


def test_users_property_returns_only_user_role_identities():
    identities = [*_users(), Identity(label="root", role=Role.ADMIN, headers={})]
    manager = SessionManager(identities)
    labels = {u.label for u in manager.users}
    assert labels == {"user-a", "user-b"}
