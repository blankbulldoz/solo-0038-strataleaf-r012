"""Identity, grants and the per-call authorization context.

A database starts in ``open`` mode so an unconfigured handle behaves like the
baseline API.  Defining the first identity closes the database: from then on
every call needs a resolved identity and is checked against that identity's
current grant.  Grants are always re-read inside the transaction that performs
the work, so a concurrent ``define``/``update``/``revoke`` cannot be raced.

An identity carries three independent capabilities: the collections it may
read, the collections it may write and whether it is an administrator.  The
grant is an authorization statement, never a credential: anyone able to open
the database file or a backup is outside this boundary (see the docs).
"""
from dataclasses import dataclass

from .codec import digest, dumps, loads, name
from .errors import Conflict, DatabaseError, InvalidDocument, PermissionDenied

WILDCARD = "*"
OPEN = "open"
ENFORCED = "enforced"
_DEFAULT = object()


def _collection_set(values, label):
    if isinstance(values, str) or not isinstance(values, (list, tuple, set, frozenset)):
        raise InvalidDocument(label + " must be a collection name list")
    result = set()
    for value in values:
        if value == WILDCARD:
            result.add(WILDCARD)
        else:
            name(value)
            result.add(value)
    return frozenset(result)


@dataclass(frozen=True)
class Grant:
    """Readable collections, writable collections and the admin capability."""
    read: frozenset = frozenset()
    write: frozenset = frozenset()
    admin: bool = False

    def __post_init__(self):
        if not isinstance(self.admin, bool):
            raise InvalidDocument("admin must be boolean")
        for label, values in (("read", self.read), ("write", self.write)):
            if not isinstance(values, frozenset) or any(not isinstance(v, str) for v in values):
                raise InvalidDocument(label + " must be a frozenset of names")
            for value in values:
                if value != WILDCARD:
                    name(value)
        if self.admin:
            object.__setattr__(self, "read", frozenset({WILDCARD}))
            object.__setattr__(self, "write", frozenset({WILDCARD}))

    @classmethod
    def make(cls, read=(), write=(), admin=False):
        return cls(_collection_set(read, "read"), _collection_set(write, "write"), admin)

    @classmethod
    def decode(cls, text):
        try:
            payload = loads(text)
            if not isinstance(payload, dict) or set(payload) != {"admin", "read", "write"}:
                raise ValueError("unexpected grant payload")
            return cls.make(payload["read"], payload["write"], payload["admin"])
        except (ValueError, TypeError, KeyError) as exc:
            raise DatabaseError("stored grant is not readable") from exc

    def payload(self):
        return {"read": sorted(self.read), "write": sorted(self.write), "admin": self.admin}

    def encode(self):
        return dumps(self.payload())

    @property
    def fingerprint(self):
        return digest(self.payload())

    def can_read(self, collection):
        return self.admin or WILDCARD in self.read or collection in self.read

    def can_write(self, collection):
        return self.admin or WILDCARD in self.write or collection in self.write


GRANT_ADMIN = Grant(frozenset(), frozenset(), True)


@dataclass(frozen=True)
class Principal:
    """An identity name.  Permissions are resolved from storage on every call."""
    name: str

    def __post_init__(self):
        name(self.name)


class Authority:
    """The authorization context of one call, bound to a transaction."""

    def __init__(self, store, connection, principal):
        row = connection.execute("SELECT value FROM meta WHERE key='access_mode'").fetchone()
        self.mode = row[0] if row is not None else OPEN
        if principal is None:
            if self.mode == ENFORCED:
                raise PermissionDenied("this database requires an identity")
            self.name = None
            self.grant = GRANT_ADMIN
            return
        identity = principal.name if isinstance(principal, Principal) else principal
        try:
            name(identity)
        except InvalidDocument as exc:
            raise PermissionDenied("unknown or unauthorized identity") from exc
        row = connection.execute("SELECT grant FROM principals WHERE name=?", (identity,)).fetchone()
        if row is None:
            raise PermissionDenied("unknown or unauthorized identity")
        self.name = identity
        self.grant = Grant.decode(row[0])

    @property
    def fingerprint(self):
        return self.grant.fingerprint

    def can_read(self, collection):
        return self.grant.can_read(collection)

    def can_write(self, collection):
        return self.grant.can_write(collection)

    def require_read(self, collection):
        if not self.grant.can_read(collection):
            raise PermissionDenied("identity may not read collection: " + collection)

    def require_write(self, collection):
        if not self.grant.can_write(collection):
            raise PermissionDenied("identity may not write collection: " + collection)

    def require_admin(self):
        if not self.grant.admin:
            raise PermissionDenied("identity may not administer this database")


def authorize(store, connection, principal):
    return Authority(store, connection, principal)


def _summary(principal_name, grant, epoch):
    return {"name": principal_name, **grant.payload(), "digest": grant.fingerprint, "auth_epoch": epoch}


class AccessControl:
    """Manage identities and authorization epochs."""

    def __init__(self, store, principal=None):
        self.store = store
        self.principal = principal

    def mode(self):
        with self.store.read():
            return self.store.get("access_mode")

    def epoch(self):
        with self.store.read():
            return int(self.store.get("auth_epoch"))

    def _bump(self, connection):
        epoch = int(connection.execute("SELECT value FROM meta WHERE key='auth_epoch'").fetchone()[0]) + 1
        connection.execute("UPDATE meta SET value=? WHERE key='auth_epoch'", (str(epoch),))
        return epoch

    def _actor(self, principal):
        return self.principal if principal is _DEFAULT else principal

    def _other_administrator(self, connection, principal_name):
        for row in connection.execute("SELECT name,grant FROM principals WHERE name<>?", (principal_name,)):
            if Grant.decode(row["grant"]).admin:
                return row["name"]
        return None

    def define(self, principal_name, read=(), write=(), admin=False, principal=_DEFAULT):
        name(principal_name)
        grant = Grant.make(read, write, admin)
        encoded = grant.encode()
        with self.store.atomic(writable=True) as connection:
            existing = connection.execute("SELECT COUNT(*) FROM principals").fetchone()[0]
            if existing:
                authorize(self.store, connection, self._actor(principal)).require_admin()
            elif self._actor(principal) is not None:
                # Bootstrap must come from the anonymous local caller: a named
                # identity cannot authorize the creation of the first grant.
                raise PermissionDenied("the first identity must be defined by the local operator")
            if connection.execute("SELECT 1 FROM principals WHERE name=?", (principal_name,)).fetchone():
                raise Conflict("identity already defined: " + principal_name)
            connection.execute("INSERT INTO principals VALUES (?,?)", (principal_name, encoded))
            connection.execute("UPDATE meta SET value=? WHERE key='access_mode'", (ENFORCED,))
            epoch = self._bump(connection)
        return _summary(principal_name, grant, epoch)

    def update(self, principal_name, read=(), write=(), admin=False, principal=_DEFAULT):
        name(principal_name)
        grant = Grant.make(read, write, admin)
        encoded = grant.encode()
        with self.store.atomic(writable=True) as connection:
            authority = authorize(self.store, connection, self._actor(principal))
            authority.require_admin()
            if not connection.execute("SELECT 1 FROM principals WHERE name=?", (principal_name,)).fetchone():
                raise PermissionDenied("unknown or unauthorized identity")
            if not grant.admin and not self._other_administrator(connection, principal_name):
                raise Conflict("cannot remove the last administrator")
            connection.execute("UPDATE principals SET grant=? WHERE name=?", (encoded, principal_name))
            epoch = self._bump(connection)
        return _summary(principal_name, grant, epoch)

    def revoke(self, principal_name, principal=_DEFAULT):
        name(principal_name)
        with self.store.atomic(writable=True) as connection:
            authority = authorize(self.store, connection, self._actor(principal))
            authority.require_admin()
            if not connection.execute("SELECT 1 FROM principals WHERE name=?", (principal_name,)).fetchone():
                raise PermissionDenied("unknown or unauthorized identity")
            if not self._other_administrator(connection, principal_name):
                raise Conflict("cannot revoke the last administrator")
            connection.execute("DELETE FROM principals WHERE name=?", (principal_name,))
            # Revocation releases the identity's holds explicitly: its cursors
            # stop validating because the grant fingerprint changes, and its
            # pins/consumer positions no longer keep history alive.
            pins = connection.execute("DELETE FROM pins WHERE owner=?", (principal_name,)).rowcount
            consumers = connection.execute("DELETE FROM consumers WHERE owner=?", (principal_name,)).rowcount
            epoch = self._bump(connection)
        return {"name": principal_name, "revoked": True, "released_pins": pins,
                "released_consumers": consumers, "auth_epoch": epoch}

    def describe(self, principal_name, principal=_DEFAULT):
        name(principal_name)
        with self.store.read() as connection:
            authority = authorize(self.store, connection, self._actor(principal))
            if not authority.grant.admin and authority.name != principal_name:
                raise PermissionDenied("identity may only describe itself")
            row = connection.execute("SELECT grant FROM principals WHERE name=?", (principal_name,)).fetchone()
            if row is None:
                raise PermissionDenied("unknown or unauthorized identity")
            grant = Grant.decode(row[0])
            return _summary(principal_name, grant, int(self.store.get("auth_epoch")))

    def list(self, principal=_DEFAULT):
        with self.store.read() as connection:
            authorize(self.store, connection, self._actor(principal)).require_admin()
            epoch = int(self.store.get("auth_epoch"))
            return [_summary(row["name"], Grant.decode(row["grant"]), epoch)
                    for row in connection.execute("SELECT name,grant FROM principals ORDER BY name")]
