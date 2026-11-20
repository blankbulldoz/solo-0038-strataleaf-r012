from .access import authorize
from .codec import dumps, loads, name
from .errors import Conflict, NotFound
from .mvcc import visible_rows
from .schema import normalize_schema, validate_document


class Catalog:
    def __init__(self, store, principal=None):
        self.store = store
        self.principal = principal

    def create(self, collection, schema=None):
        name(collection)
        normalized = normalize_schema({} if schema is None else schema)
        with self.store.atomic(writable=True) as connection:
            authorize(self.store, connection, self.principal).require_admin()
            if connection.execute("SELECT 1 FROM collections WHERE name=?", (collection,)).fetchone():
                raise Conflict("collection already exists: " + collection)
            connection.execute("INSERT INTO collections VALUES (?,?,1)", (collection, dumps(normalized)))
            self.store.set("catalog_epoch", int(self.store.get("catalog_epoch")) + 1)
        return self.describe(collection)

    def describe(self, collection):
        with self.store.read() as connection:
            authority = authorize(self.store, connection, self.principal)
            row = connection.execute("SELECT * FROM collections WHERE name=?", (collection,)).fetchone()
            if row is None:
                raise NotFound("unknown collection: " + collection)
            if not authority.grant.admin and not authority.can_read(collection):
                raise NotFound("unknown collection: " + collection)
            return {"name": row["name"], "schema": loads(row["schema"]), "generation": row["generation"]}

    def list(self):
        with self.store.read() as connection:
            authority = authorize(self.store, connection, self.principal)
            return [{"name": row["name"], "schema": loads(row["schema"]), "generation": row["generation"]}
                    for row in connection.execute("SELECT * FROM collections ORDER BY name")
                    if authority.can_read(row["name"])]

    def evolve(self, collection, schema, expected_generation):
        normalized = normalize_schema(schema)
        with self.store.atomic(writable=True) as connection:
            authorize(self.store, connection, self.principal).require_admin()
            row = connection.execute("SELECT * FROM collections WHERE name=?", (collection,)).fetchone()
            if row is None:
                raise NotFound("unknown collection: " + collection)
            if row["generation"] != expected_generation:
                raise Conflict("schema generation changed")
            for document in visible_rows(connection, collection, int(self.store.get("head"))):
                validate_document(loads(document["body"]), normalized)
            generation = expected_generation + 1
            connection.execute("UPDATE collections SET schema=?,generation=? WHERE name=?",
                               (dumps(normalized), generation, collection))
            self.store.set("catalog_epoch", int(self.store.get("catalog_epoch")) + 1)
        return generation
