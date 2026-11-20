"""Read a pinned npm OSV snapshot without sending dependency names to a service."""
import json
import os
import re
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from semantic_version import Version


@lru_cache(maxsize=8)
def _run_manifest(base, run_id):
    # A running plan uses one edition even if another client refreshes the pointer.
    return json.loads((base / "active.json").read_bytes())


def snapshot(directory):
    base = Path(directory).resolve()
    try:
        run_id = os.environ.get("DEPLOOM_RUN_ID")
        manifest = _run_manifest(base, run_id) if run_id else json.loads((base / "active.json").read_bytes())
        digest = manifest["sha256"]
        if (type(manifest["schema"]) is not int or manifest["schema"] != 1 or manifest["ecosystem"] != "npm"
                or not re.fullmatch("[0-9a-f]{64}", digest)):
            raise ValueError("invalid manifest")
        db = base / (digest + ".sqlite")
        published = manifest["published"]
        if type(published) is not int or db.stat().st_size != manifest["unpacked"]:
            raise ValueError("invalid snapshot")
        age = time.time() - published
        status = "ready" if -300 <= age <= 7 * 86400 else "stale"
        return db, {"status": status, "sha256": digest,
                    "publishedAt": datetime.fromtimestamp(published, timezone.utc).isoformat()}
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return None, {"status": "unavailable"}


def parse(value):
    return Version(str(Version(value)).split("+", 1)[0])


def matches(version, exact, ranges):
    if str(version) in exact:
        return True
    uncertain = False
    for kind, events in ranges:
        if kind not in {"SEMVER", "ECOSYSTEM"}:
            uncertain = True
            continue
        active = False
        previous = None
        try:
            if not events or "introduced" not in events[0]:
                raise ValueError()
            for event in events:
                ((action, raw),) = event.items()
                bound = None if (action, raw) == ("introduced", "0") else parse(raw)
                if (action not in {"introduced", "fixed", "last_affected", "limit"}
                        or (previous is not None and (bound is None or bound < previous))):
                    raise ValueError()
                previous = bound
                if bound is None or version > bound or (version == bound and action != "last_affected"):
                    active = action == "introduced"
            if active:
                return True
        except (TypeError, ValueError, AttributeError):
            uncertain = True
    if uncertain or (not exact and not ranges):
        raise ValueError("unsupported OSV range")
    return False


def query(directory, package, versions, private_scopes="", public_names=""):
    db, info = snapshot(directory)
    if info["status"] != "ready":
        raise ValueError("offline OSV " + info["status"])
    if package.split("/")[0] in private_scopes.split(","):
        raise ValueError("private package outside public npm OSV coverage")
    with closing(sqlite3.connect(db.as_uri() + "?mode=ro&immutable=1", uri=True)) as conn:
        conn.execute("PRAGMA trusted_schema=OFF")
        records = [(i, severity, json.loads(exact), json.loads(ranges))
                   for i, severity, exact, ranges in conn.execute(
                       "SELECT id,severity,versions,ranges FROM advisory WHERE name=?", (package,))]
    if not records and package not in public_names.split(","):
        raise ValueError("package coverage unconfirmed in public npm OSV")
    result = {}
    for raw in versions:
        findings = {}
        try:
            version = parse(raw)
            for identifier, severity, exact, ranges in records:
                if matches(version, exact, ranges):
                    if str(severity).lower() not in {"critical", "high", "medium", "moderate", "low"}:
                        raise ValueError("unrated advisory")
                    findings[identifier] = {"id": identifier, "database_specific": {"severity": severity}}
        except (ValueError, TypeError):
            continue  # Incomplete evidence for this exact version only.
        result[raw] = list(findings.values())
    if not result and versions:
        raise ValueError("incomplete OSV version or severity evidence")
    return result
