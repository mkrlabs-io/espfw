"""SQLite signature store.

The store keeps the full canonical and raw form of every harvested function,
not only the digest the matcher needs, so anything derived from it can be
recomputed after a canonicalizer change without rebuilding the corpus.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from espfw import cache, provenance
from espfw.canon import CANON_VERSION
from espfw.canon.xtensa import CanonicalForm
from espfw.corpus.models import (
    BuildKey,
    BuildRecord,
    CorpusListing,
    GcResult,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS builds (
    id              INTEGER PRIMARY KEY,
    idf_version     TEXT NOT NULL,
    config_hash     TEXT NOT NULL,
    chip            TEXT NOT NULL,
    toolchain       TEXT NOT NULL,
    config_name     TEXT NOT NULL,
    config_text     TEXT,
    canon_version   INTEGER NOT NULL,
    objdump_version TEXT,
    created_at      TEXT NOT NULL,
    UNIQUE (idf_version, config_hash, chip, toolchain, canon_version)
);

CREATE TABLE IF NOT EXISTS functions (
    id                INTEGER PRIMARY KEY,
    build_id          INTEGER NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    component         TEXT,
    object            TEXT,
    origin            TEXT NOT NULL,   -- 'archive' or 'linked'
    vaddr             INTEGER,
    size              INTEGER NOT NULL,
    instruction_count INTEGER NOT NULL,
    digest            TEXT NOT NULL,
    canonical_text    TEXT NOT NULL,
    raw_text          TEXT,
    call_edges        TEXT,
    literals          TEXT,
    immediates        TEXT,
    indirect_calls    INTEGER DEFAULT 0,
    branch_count      INTEGER DEFAULT 0,
    prologue          TEXT,
    -- String literals the function references. Not part of the match key:
    -- anchors have to survive the codegen changes that defeat body comparison,
    -- which they cannot do if they alter the form being compared.
    strings           TEXT
);

CREATE INDEX IF NOT EXISTS idx_functions_digest ON functions(digest);
CREATE INDEX IF NOT EXISTS idx_functions_build  ON functions(build_id);
CREATE INDEX IF NOT EXISTS idx_functions_name   ON functions(name);
"""

class CorpusStore:
    def __init__(self, conn: sqlite3.Connection, path: Path) -> None:
        self.conn = conn
        self.path = path
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(SCHEMA)

    # -- writing --------------------------------------------------------------

    def create_build(
        self,
        key: BuildKey,
        config_name: str,
        config_text: str | None,
        objdump_version: str | None,
    ) -> int:
        cur = self.conn.execute(
            """INSERT OR REPLACE INTO builds
               (idf_version, config_hash, chip, toolchain, config_name,
                config_text, canon_version, objdump_version, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                key.idf_version,
                key.config_hash,
                key.chip,
                key.toolchain,
                config_name,
                config_text,
                CANON_VERSION,
                objdump_version,
                datetime.now(UTC).isoformat(timespec="seconds"),
            ),
        )
        build_id = cur.lastrowid
        assert build_id is not None
        # REPLACE drops the old row but the cascade only fires on DELETE, so
        # orphaned functions are cleared explicitly.
        self.conn.execute(
            "DELETE FROM functions WHERE build_id NOT IN (SELECT id FROM builds)"
        )
        return build_id

    def add_functions(
        self,
        build_id: int,
        entries: list[tuple[str, str | None, str | None, str, int | None, CanonicalForm]],
    ) -> None:
        """Insert (name, component, object, origin, vaddr, form) rows."""
        self.conn.executemany(
            """INSERT INTO functions
               (build_id, name, component, object, origin, vaddr, size,
                instruction_count, digest, canonical_text, raw_text, call_edges,
                literals, immediates, indirect_calls, branch_count, prologue,
                strings)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                (
                    build_id,
                    name,
                    component,
                    obj,
                    origin,
                    vaddr,
                    form.size,
                    form.instruction_count,
                    form.digest,
                    form.canonical_text,
                    form.raw_text,
                    json.dumps(form.call_edges),
                    json.dumps(form.literals),
                    json.dumps(form.immediates),
                    form.indirect_calls,
                    form.branch_count,
                    form.prologue,
                    json.dumps(form.strings),
                )
                for name, component, obj, origin, vaddr, form in entries
            ],
        )

    def commit(self) -> None:
        self.conn.commit()

    def remove_build(self, build_id: int) -> int:
        """Delete one corpus build and its signatures, returning the count.

        `gc` only removes builds made stale by a canonicalizer bump. A build that
        is stale for any *other* reason — harvested before a build-script fix, say
        — is invisible to it, and leaving one in place would let it match.
        """
        count = self.conn.execute(
            "SELECT COUNT(*) c FROM functions WHERE build_id=?", (build_id,)
        ).fetchone()["c"]
        self.conn.execute("DELETE FROM functions WHERE build_id=?", (build_id,))
        self.conn.execute("DELETE FROM builds WHERE id=?", (build_id,))
        return int(count)

    # -- reading --------------------------------------------------------------

    def builds_for(
        self, idf_version: str, chip: str, toolchain: str | None = None
    ) -> list[BuildRecord]:
        """Every cached build for a version/chip."""
        sql = """SELECT * FROM builds
                 WHERE idf_version=? AND chip=? AND canon_version=?"""
        args: list = [idf_version, chip, CANON_VERSION]
        if toolchain:
            sql += " AND toolchain=?"
            args.append(toolchain)
        rows = self.conn.execute(sql, args).fetchall()
        return [self._to_record(r) for r in rows]

    def current_builds(self, chip: str) -> list[BuildRecord]:
        """Every comparable corpus build for a chip, in deterministic order."""
        rows = self.conn.execute(
            """SELECT * FROM builds
               WHERE chip=? AND canon_version=?
               ORDER BY idf_version, config_name, config_hash, toolchain, id""",
            (chip, CANON_VERSION),
        ).fetchall()
        return [self._to_record(row) for row in rows]

    def list_builds(self, version: str | None = None) -> CorpusListing:
        sql = "SELECT * FROM builds"
        args: list = []
        if version:
            sql += " WHERE idf_version=?"
            args.append(version)
        sql += " ORDER BY idf_version, chip, created_at"
        rows = self.conn.execute(sql, args).fetchall()

        listing = CorpusListing(
            db_path=str(self.path),
            builds=[self._to_record(r) for r in rows],
            canon_version=CANON_VERSION,
            provenance=provenance.current(),
        )
        stale = [b for b in listing.builds if b.stale]
        if stale:
            listing.warnings.append(
                f"{len(stale)} build(s) were made by canonicalizer version(s) other "
                f"than {CANON_VERSION} and are not comparable with fresh analyses; "
                "`espfw corpus gc` removes them"
            )
        if not listing.builds:
            listing.warnings.append(
                "the corpus is empty; `espfw corpus build --version <v> --chip <chip>` "
                "populates it (this takes minutes to hours and is never implicit)"
            )
        return listing

    def signatures_for_digests(
        self, chip: str, digests: set[str]
    ) -> list[sqlite3.Row]:
        """Matching rows from every current corpus build for ``chip``.

        Restricting the query to target digests avoids loading canonical/raw
        bodies for an entire multi-version corpus when exact matching only needs
        the handful of forms present in the image.
        """
        if not digests:
            return []

        out: list[sqlite3.Row] = []
        ordered = sorted(digests)
        for start in range(0, len(ordered), 500):
            chunk = ordered[start : start + 500]
            placeholders = ",".join("?" for _ in chunk)
            out.extend(
                self.conn.execute(
                    f"""SELECT DISTINCT f.build_id, f.name, f.component, f.origin,
                               f.digest
                        FROM functions f
                        JOIN builds b ON b.id=f.build_id
                        WHERE b.chip=? AND b.canon_version=?
                          AND f.digest IN ({placeholders})
                        ORDER BY f.digest, f.name, f.origin, f.build_id""",
                    [chip, CANON_VERSION, *chunk],
                ).fetchall()
            )
        return out

    def function_count(self, build_id: int) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) c FROM functions WHERE build_id=?", (build_id,)
        ).fetchone()
        return int(row["c"])

    # -- maintenance ----------------------------------------------------------

    def gc(self, dry_run: bool = False) -> GcResult:
        rows = self.conn.execute(
            "SELECT * FROM builds WHERE canon_version != ?", (CANON_VERSION,)
        ).fetchall()
        ids = [r["id"] for r in rows]
        result = GcResult(
            db_path=str(self.path),
            dry_run=dry_run,
            stale_builds=[
                f"{r['idf_version']} / {r['chip']} / {r['config_name']} "
                f"(canonicalizer v{r['canon_version']})"
                for r in rows
            ],
            provenance=provenance.current(),
        )
        if not ids:
            return result

        placeholders = ",".join("?" * len(ids))
        count = self.conn.execute(
            f"SELECT COUNT(*) c FROM functions WHERE build_id IN ({placeholders})", ids
        ).fetchone()["c"]
        result.functions_removed = int(count)

        if not dry_run:
            self.conn.execute(
                f"DELETE FROM functions WHERE build_id IN ({placeholders})", ids
            )
            self.conn.execute(f"DELETE FROM builds WHERE id IN ({placeholders})", ids)
            self.conn.commit()
            self.conn.execute("VACUUM")
        return result

    def _to_record(self, row: sqlite3.Row) -> BuildRecord:
        counts = self.conn.execute(
            """SELECT origin, COUNT(*) c FROM functions
               WHERE build_id=? GROUP BY origin""",
            (row["id"],),
        ).fetchall()
        by_origin = {r["origin"]: r["c"] for r in counts}
        return BuildRecord(
            id=row["id"],
            key=BuildKey(
                idf_version=row["idf_version"],
                config_hash=row["config_hash"],
                chip=row["chip"],
                toolchain=row["toolchain"],
            ),
            config_name=row["config_name"],
            canon_version=row["canon_version"],
            objdump_version=row["objdump_version"],
            created_at=row["created_at"],
            function_count=sum(by_origin.values()),
            archive_functions=by_origin.get("archive", 0),
            linked_functions=by_origin.get("linked", 0),
            stale=row["canon_version"] != CANON_VERSION,
        )


@contextlib.contextmanager
def open_store(cache_dir: Path | None = None) -> Iterator[CorpusStore]:
    path = cache.corpus_db(cache_dir)
    conn = sqlite3.connect(path)
    try:
        yield CorpusStore(conn, path)
    finally:
        conn.close()
