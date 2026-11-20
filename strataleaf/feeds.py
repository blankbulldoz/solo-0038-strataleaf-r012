from .access import authorize
from .codec import loads, name
from .errors import Conflict, InvalidDocument, NotFound
from .mvcc import checked_revision


class ChangeFeed:
    """Change subscription.  Consumers are identity-bound and only see commits
    that touch collections their identity may read; a commit is delivered whole
    only when every collection in it is readable, otherwise it is withheld."""
    def __init__(self, store, principal=None):
        self.store = store
        self.principal = principal

    @staticmethod
    def _visible(commit, authority):
        collections = {operation["collection"] for operation in commit.get("operations", [])}
        return all(authority.can_read(collection) for collection in collections)

    def _commits(self, connection, since, limit, authority):
        output = []
        for row in connection.execute("SELECT payload FROM commits WHERE rev>? ORDER BY rev", (since,)):
            commit = loads(row[0])
            if not self._visible(commit, authority):
                continue
            output.append(commit)
            if len(output) >= limit:
                break
        return output

    def read(self, since, limit=100):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise InvalidDocument("feed limit must be between 1 and 1000 commits")
        with self.store.read() as connection:
            authority = authorize(self.store, connection, self.principal)
            checked_revision(self.store, since)
            return self._commits(connection, since, limit, authority)

    def register(self, consumer, since=None):
        name(consumer)
        with self.store.atomic() as connection:
            authority = authorize(self.store, connection, self.principal)
            since = checked_revision(self.store, since)
            if connection.execute("SELECT 1 FROM consumers WHERE name=?", (consumer,)).fetchone():
                raise Conflict("consumer already registered")
            connection.execute("INSERT INTO consumers VALUES (?,?,?)", (consumer, since, authority.name or ""))
        return since

    def _owned(self, connection, consumer, authority):
        row = connection.execute("SELECT ack, owner FROM consumers WHERE name=?", (consumer,)).fetchone()
        if row is None:
            raise NotFound("unknown consumer")
        if not authority.grant.admin and row["owner"] != (authority.name or ""):
            raise NotFound("unknown consumer")
        return row

    def position(self, consumer):
        with self.store.read() as connection:
            authority = authorize(self.store, connection, self.principal)
            return self._owned(connection, consumer, authority)["ack"]

    def acknowledge(self, consumer, revision):
        with self.store.atomic() as connection:
            authority = authorize(self.store, connection, self.principal)
            revision = checked_revision(self.store, revision)
            row = self._owned(connection, consumer, authority)
            if revision < row["ack"]:
                raise Conflict("consumer acknowledgement cannot move backwards")
            # Advancing a position past commits this identity cannot read is
            # allowed: a position reveals nothing, and withholding it would
            # deadlock retention behind a hidden commit.
            connection.execute("UPDATE consumers SET ack=? WHERE name=?", (revision, consumer))
        return revision

    def release(self, consumer):
        with self.store.atomic() as connection:
            authority = authorize(self.store, connection, self.principal)
            if not self._owned(connection, consumer, authority):
                raise NotFound("unknown consumer")
            connection.execute("DELETE FROM consumers WHERE name=?", (consumer,))