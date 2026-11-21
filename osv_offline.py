"""Read a pinned npm OSV snapshot without sending dependency names to a service."""
import json
import os
import re
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass, field
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
        status = "ready" if -300 <= age < 7 * 86400 else "stale"
        return db, {"status": status, "sha256": digest,
                    "publishedAt": datetime.fromtimestamp(published, timezone.utc).isoformat()}
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return None, {"status": "unavailable"}


def parse(value):
    return Version(str(Version(value)).split("+", 1)[0])


def is_exact_version(value):
    try:
        return str(Version(value)) == value
    except (ValueError, TypeError):
        return False


def matches(version, exact, ranges, *, raw_version=None):
    spelling = raw_version if raw_version is not None else str(version)
    if spelling in exact:
        return True
    # Version lists can identify a concrete build; equal semver precedence
    # alone cannot establish whether another build has the same findings.
    uncertain = any(isinstance(other, str) and other.partition("+")[0] == spelling.partition("+")[0]
                    for other in exact)
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


_SEVERITY_RANK = {"": 0, "low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}


@dataclass
class PairAssessment:
    # A matching advisory remains a finding even when the snapshot cannot rate it.
    findings: dict[str, str] = field(default_factory=dict)
    reason: str = ""

    def entries(self):
        return [{"id": identifier, "database_specific": {"severity": severity}}
                for identifier, severity in self.findings.items()]


def _names(value):
    return {item.strip() for item in value.split(",") if item.strip()}


def private_package(package, private_scopes):
    return package.partition("/")[0].casefold() in {scope.casefold() for scope in _names(private_scopes)}


def assess(directory, package, versions, private_scopes="", public_names=""):
    """Return separate evidence and the first blocking reason for each exact pair."""
    db, info = snapshot(directory)
    if info["status"] != "ready":
        code = "SNAPSHOT_STALE" if info["status"] == "stale" else "SNAPSHOT_UNAVAILABLE"
        return {raw: PairAssessment(reason=code) for raw in versions}
    return assess_database(db, package, versions, private_scopes, public_names)


def assess_database(db, package, versions, private_scopes="", public_names=""):
    """Evaluate a supplied database; the caller is responsible for provenance and freshness."""
    def unknown(code):
        return {raw: PairAssessment(reason=code) for raw in versions}

    if private_package(package, private_scopes):
        return unknown("PRIVATE_SCOPE_EXCLUDED")
    try:
        with closing(sqlite3.connect(db.as_uri() + "?mode=ro&immutable=1", uri=True)) as conn:
            conn.execute("PRAGMA trusted_schema=OFF")
            records = [(identifier, severity, json.loads(exact), json.loads(ranges))
                       for identifier, severity, exact, ranges in conn.execute(
                           "SELECT id,severity,versions,ranges FROM advisory WHERE name=?", (package,))]
        if any(not isinstance(identifier, str) or not identifier or not isinstance(exact, list)
               or not all(isinstance(version, str) for version in exact)
               or not isinstance(ranges, list) for identifier, _, exact, ranges in records):
            raise ValueError("invalid advisory row")
    except (OSError, sqlite3.Error, TypeError, ValueError):
        return unknown("SNAPSHOT_READ_ERROR")

    if not records and package not in _names(public_names):
        return unknown("PUBLIC_PACKAGE_UNCONFIRMED")
    result = {}
    for raw in versions:
        item = result[raw] = PairAssessment()
        try:
            version = parse(raw)
        except (ValueError, TypeError):
            item.reason = "INVALID_EXACT_VERSION"
            continue
        for identifier, severity, exact, ranges in records:
            try:
                affected = matches(version, exact, ranges, raw_version=raw)
            except (ValueError, TypeError, AttributeError):
                if not item.reason:
                    item.reason = "UNSUPPORTED_OSV_RANGE"
                continue
            if affected:
                rank = str(severity).lower()
                if rank not in _SEVERITY_RANK:
                    rank = ""
                previous = item.findings.get(identifier, "")
                item.findings[identifier] = max((previous, rank), key=_SEVERITY_RANK.get)
        if "" in item.findings.values():
            item.reason = "MISSING_SEVERITY"
    return result


def supplement(assessment, registry_record):
    """Keep every positive OSV observation; only a matching ID can fill in its severity."""
    known_ids = {identifier.upper(): identifier for identifier in assessment.findings}
    registry_groups = {}
    for advisory in registry_record.advisories:
        registry_groups.setdefault(advisory.identifier, []).append(advisory)
    # Repeated ranges can carry the GHSA URL on only one of several rows.
    # A CVE identifier and its GHSA URL can both be present in the OSV snapshot.
    groups = {}
    for local_id, advisories in registry_groups.items():
        canonicals = {advisory.canonical_id for advisory in advisories if advisory.canonical_id}
        ghsas = {identifier for identifier in canonicals if identifier.startswith("GHSA-")}
        if len(ghsas) > 1 or (local_id.upper().startswith("GHSA-") and ghsas and local_id.upper() not in ghsas):
            raise ValueError("conflicting registry advisory identifiers")
        if ghsas:
            identifier = next(iter(ghsas))
        elif canonicals:
            identifier = min(canonicals)
        elif local_id in assessment.findings and re.fullmatch(r"[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+", local_id):
            identifier = local_id
        else:
            identifier = "registry:" + local_id
        aliases, ranks = groups.setdefault(identifier, (set(), []))
        if not local_id.isdecimal() and local_id.upper() in known_ids:
            aliases.add(known_ids[local_id.upper()])
        if identifier.upper() in known_ids:
            aliases.add(known_ids[identifier.upper()])
        ranks.extend(advisory.severity for advisory in advisories)

    merged = dict(assessment.findings)
    for identifier, (aliases, ranks) in groups.items():
        for alias in aliases:
            ranks.append(merged.pop(alias, ""))
        merged[identifier] = max(ranks, key=_SEVERITY_RANK.get)
    return PairAssessment(merged, "MISSING_SEVERITY" if "" in merged.values() else "")


def query(directory, package, versions, private_scopes="", public_names=""):
    """Compatibility surface for callers that consume only complete results."""
    assessed = assess(directory, package, versions, private_scopes, public_names)
    result = {version: item.entries() for version, item in assessed.items() if not item.reason}
    if assessed and not result:
        codes = sorted({item.reason for item in assessed.values()})
        raise ValueError("offline OSV: " + ", ".join(code.lower() for code in codes))
    return result
