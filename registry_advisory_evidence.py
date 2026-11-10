"""Exact-version evidence from an explicitly approved npm registry."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlsplit

from semantic_version import Version

SOURCE = "REGISTRY_BULK_ADVISORY"
_ENDPOINT = "/-/npm/v1/security/advisories/bulk"
_MAX_BODY_BYTES = 2 * 1024 * 1024
_NAME = re.compile(r"(?:@[a-zA-Z0-9_.-]+/)?[a-zA-Z0-9_.-]+")
_SEVERITIES = frozenset({"critical", "high", "moderate", "low"})


@dataclass(frozen=True)
class RegistryAdvisory:
    identifier: str
    severity: str
    vulnerable_range: str


@dataclass(frozen=True)
class RegistryAdvisoryEvidence:
    status: str
    reason: str
    advisories: tuple[RegistryAdvisory, ...] = ()
    response_sha256: str | None = None
    retrieved_at: str | None = None
    source: str = SOURCE


def _unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def registry_advisory_source_matches(registry: str, approved_registry: str) -> bool:
    try:
        parsed = urlsplit(registry)
        return bool(
            registry.rstrip("/") == approved_registry.rstrip("/")
            and parsed.scheme == "https" and parsed.hostname
            and not (parsed.username or parsed.password or parsed.query or parsed.fragment)
            and not any(c.isspace() or c in r"\%?#" for c in registry)
            and all(part not in {".", ".."} for part in parsed.path.split("/"))
            and (parsed.port is None or 0 < parsed.port < 65536)
        )
    except ValueError:
        return False


def valid_registry_advisory_name(name: str) -> bool:
    return (len(name) <= 214 and bool(_NAME.fullmatch(name))
            and not any(part in {".", ".."} for part in name.split("/")))


def query_registry_advisories(
    session,
    registry: str,
    approved_registry: str,
    pairs: list[tuple[str, str]],
    *,
    matches: Callable[[str, str], bool] | None = None,
    match_many: Callable[[list[tuple[str, str]]], list[bool | None]] | None = None,
    timeout: tuple[float, float],
    trust_omitted_packages: bool = False,
    max_match_evaluations: int | None = None,
) -> dict[tuple[str, str], RegistryAdvisoryEvidence]:
    """Query one trusted registry. The host supplies approval and omission policy.

    `matches(range, version)` or `match_many(pairs)` must implement npm semver.
    A batch result has exactly one bool/None per comparison in the same order;
    None denotes an unsupported range. Missing package keys are unknown unless the host
    has established that omission is the registry's negative response.
    """
    requested = tuple(dict.fromkeys(pairs))
    if not requested:
        return {}

    def unknown(reason):
        return {pair: RegistryAdvisoryEvidence("UNKNOWN", reason) for pair in requested}

    if not registry_advisory_source_matches(registry, approved_registry):
        return unknown("REGISTRY_NOT_APPROVED")

    payload: dict[str, list[str]] = {}
    try:
        for name, version in requested:
            if not valid_registry_advisory_name(name) or str(Version(version)) != version:
                raise ValueError("invalid exact package/version")
            payload.setdefault(name, []).append(version)
    except (TypeError, ValueError):
        return unknown("INVALID_EXACT_PAIR")

    try:
        with session.post(
            registry.rstrip("/") + _ENDPOINT, json=payload, timeout=timeout,
            allow_redirects=False, stream=True,
        ) as response:
            if response.status_code != 200:
                return unknown("REGISTRY_HTTP_ERROR")
            body = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                if len(body) + len(chunk) > _MAX_BODY_BYTES:
                    return unknown("RESPONSE_TOO_LARGE")
                body.extend(chunk)
    except (OSError, ValueError):
        return unknown("REGISTRY_TRANSPORT_ERROR")

    try:
        data = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
        if not isinstance(data, dict) or set(data) - set(payload):
            raise ValueError("invalid registry advisory envelope")
    except (UnicodeError, ValueError):
        return unknown("INVALID_ADVISORY_RESPONSE")

    digest = hashlib.sha256(body).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()
    evidence = {}
    comparisons = {}
    prepared = {}

    def record_unknown(pair, reason):
        evidence[pair] = RegistryAdvisoryEvidence(
            "UNKNOWN", reason, response_sha256=digest, retrieved_at=timestamp)

    # Validate and budget before invoking any evaluator. Preserve first-seen
    # comparison order and deduplication across package/version pairs.
    for name, version in requested:
        pair = name, version
        records = data.get(name)
        if name not in data and not trust_omitted_packages:
            record_unknown(pair, "COVERAGE_UNCONFIRMED")
            continue
        try:
            if name not in data:
                records = []
            if not isinstance(records, list):
                raise ValueError("invalid advisory list")
            if max_match_evaluations is not None and len(records) > max_match_evaluations:
                record_unknown(pair, "MATCH_BUDGET_EXHAUSTED")
                continue
            parsed = []
            for record in records:
                if not isinstance(record, dict) or record.get("name", name) != name:
                    raise ValueError("invalid advisory package")
                identifier, severity, spec = (record.get(field) for field in ("id", "severity", "vulnerable_versions"))
                if (type(identifier) not in (int, str) or not str(identifier).strip()
                        or not isinstance(severity, str) or severity not in _SEVERITIES
                        or not isinstance(spec, str) or not spec.strip()):
                    raise ValueError("invalid advisory fields")
                key = spec, version
                if key not in comparisons:
                    if max_match_evaluations is not None and len(comparisons) >= max_match_evaluations:
                        record_unknown(pair, "MATCH_BUDGET_EXHAUSTED")
                        break
                    comparisons[key] = None
                parsed.append(RegistryAdvisory(str(identifier), severity, spec))
            if pair not in evidence:
                prepared[pair] = parsed
        except ValueError:
            record_unknown(pair, "INVALID_ADVISORY_OR_RANGE")

    if comparisons and match_many is not None:
        keys = list(comparisons)
        try:
            outcomes = match_many(keys)
            if (not isinstance(outcomes, list) or len(outcomes) != len(keys)
                    or any(value is not None and type(value) is not bool for value in outcomes)):
                raise ValueError("invalid batch range response")
            comparisons.update(zip(keys, outcomes, strict=True))
        except ValueError:
            pass  # The complete batch remains unknown; never fall back to clean.
    elif comparisons:
        for spec, version in comparisons:
            try:
                if matches is None:
                    raise ValueError("npm range matcher missing")
                comparisons[spec, version] = matches(spec, version)
            except ValueError:
                pass

    for (name, version), records in prepared.items():
        if any(type(comparisons[record.vulnerable_range, version]) is not bool for record in records):
            record_unknown((name, version), "INVALID_ADVISORY_OR_RANGE")
            continue
        matched = tuple(dict.fromkeys(record for record in records if comparisons[record.vulnerable_range, version]))
        evidence[name, version] = RegistryAdvisoryEvidence(
            "AFFECTED" if matched else "NO_REPORTED_ADVISORIES",
            "REGISTRY_EXACT_VERSION", matched, digest, timestamp,
        )
    return {pair: evidence[pair] for pair in requested}
