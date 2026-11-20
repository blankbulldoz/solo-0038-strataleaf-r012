from .access import AccessControl, authorize
from .aggregate import Aggregates
from .archive import Archives
from .catalog import Catalog
from .diagnostics import Diagnostics
from .feeds import ChangeFeed
from .indexes import Indexes
from .mvcc import read_record
from .patch import patch_document
from .query import QueryEngine
from .replica import Replication
from .retention import Retention
from .storage import Storage
from .transaction import WriteBatch
from .transfer import Transfer


class Database:
    """An embedded, single-file, revisioned JSON document database.

    ``principal`` is the identity every call of this handle acts as.  A database
    with no identities defined stays in ``open`` mode and needs none; once the
    first identity is defined every call must resolve to a known, current grant.
    The grant is re-read inside each call's transaction, so approvals and
    revocations never race with the work they authorize.
    """
    def __init__(self, path, timeout=5.0, principal=None):
        self._store = Storage(path, timeout)
        self._owns_store = True
        self._bind(principal)

    def _bind(self, principal):
        self._principal = principal
        self.access = AccessControl(self._store, principal)
        self.catalog = Catalog(self._store, principal)
        self.indexes = Indexes(self._store, principal)
        self.feed = ChangeFeed(self._store, principal)
        self.retention = Retention(self._store, principal)
        self.archives = Archives(self._store, principal)
        self.replication = Replication(self._store, principal)
        self.aggregates = Aggregates(self._store, principal)
        self.transfer = Transfer(self._store, principal)
        self.diagnostics = Diagnostics(self._store, principal)
        self._queries = QueryEngine(self._store, principal)

    @property
    def identity(self):
        return self._principal

    @property
    def revision(self):
        # The global head is metadata, not collection content: any resolved
        # identity may read it, so write-only services can target expected
        # revisions without being able to read documents.
        with self._store.read() as connection:
            authorize(self._store, connection, self._principal)
            return int(self._store.get("head"))

    def as_principal(self, principal):
        """A handle acting as another identity over the same connection.

        Used so a trusted administrative handle can hand scoped views to the
        service modules that share this database, without reopening the file.
        """
        bound = object.__new__(Database)
        bound._store = self._store
        bound._owns_store = False
        bound._bind(principal)
        return bound

    def batch(self, request_key=None):
        return WriteBatch(self._store, request_key, self._principal)

    def get(self, collection, key, revision=None):
        return read_record(self._store, collection, key, revision, self._principal)

    def query(self, collection, predicate=None, limit=100, cursor=None, revision=None, force_scan=False):
        return self._queries.select(collection, predicate, limit, cursor, revision, force_scan)

    def patch(self, collection, key, patch, expected=None):
        return patch_document(self._store, collection, key, patch, expected, self._principal)

    def checkpoint(self):
        return self._store.checkpoint()

    def close(self):
        if self._owns_store:
            self._store.close()

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.close()
