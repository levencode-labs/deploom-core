"""Collect exact workspace health facts using the owning registry client."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Iterable, Mapping

from registry_advisory_evidence import SOURCE as REGISTRY_BULK_ADVISORY
from workspace_health_policy import WorkspaceHealthFact


_MAX_REGISTRY_ADVISORY_PAIRS = 2048
_MAX_REGISTRY_RANGE_COMPARISONS = 256


def collect_workspace_health_facts(
    client,
    packuments: Mapping[str, dict],
    versions: Mapping[str, Iterable[str]],
    *,
    lag_months: int,
    osv_allowed_names: frozenset[str],
    registry_advisory_source: str | None = None,
) -> tuple[dict[tuple[str, str], WorkspaceHealthFact], dict]:
    """Deduplicate exact versions and preserve missing dates and advisories as unknown."""
    from dependency_live_roadmap_generator import (
        SEVERITY_LABELS, VulnerabilityEvidenceUnavailable,
        min_by_lag, severity_rank, version_date,
    )

    if type(lag_months) is not int or lag_months not in {3, 6, 9, 12}:
        raise ValueError("INVALID_WORKSPACE_LAG_MONTHS")
    observed_at = datetime.now(timezone.utc)
    facts = {}
    rows = []
    skipped_names = 0
    unknown_reasons: Counter[str] = Counter()
    response_digests: set[str] = set()
    candidates_by_name = {name: sorted(set(versions[name])) for name in sorted(versions)}
    registry_records = {}
    over_limit = False
    if registry_advisory_source is not None:
        pairs = [(name, version) for name, candidates in candidates_by_name.items() for version in candidates]
        over_limit = len(pairs) > _MAX_REGISTRY_ADVISORY_PAIRS
        if not over_limit:
            registry_records = client.query_registry_advisory_evidence(
                pairs, registry_advisory_source, max_match_evaluations=_MAX_REGISTRY_RANGE_COMPARISONS,
            )
    for name, candidates in candidates_by_name.items():
        meta = packuments.get(name, {})
        latest = client.latest_installable_version(name, meta, include_prerelease=False)
        latest_date = version_date(meta, latest)
        findings = {}
        if registry_advisory_source is None:
            if name in osv_allowed_names:
                try:
                    findings = client.query_osv_versions(name, candidates)
                except VulnerabilityEvidenceUnavailable:
                    findings = {}
            else:
                skipped_names += 1
        else:
            skipped_names += 1
        for version in candidates:
            observed = version_date(meta, version)
            lag_ok = None
            if (latest_date is not None and observed is not None
                    and latest_date.utcoffset() is not None and observed.utcoffset() is not None
                    and max(latest_date, observed) <= observed_at):
                try:
                    lag_ok = min_by_lag(meta, [version], lag_months, latest_override=latest) == version
                except TypeError:  # mixed aware/naive timestamps do not establish order
                    pass
            advisories = findings.get(version)
            severities = None
            if isinstance(advisories, list) and all(isinstance(item, dict) for item in advisories):
                severities = frozenset(SEVERITY_LABELS.get(severity_rank(item), "U") for item in advisories)
            provenance = None
            if registry_advisory_source is not None:
                record = registry_records.get((name, version))
                if record is None:
                    reason = "PAIR_BUDGET_EXHAUSTED" if over_limit else "EXACT_PAIR_NOT_RETURNED"
                    unknown_reasons[reason] += 1
                    provenance = [reason]
                else:
                    if record.response_sha256:
                        response_digests.add(record.response_sha256)
                    if record.status == "UNKNOWN":
                        unknown_reasons[record.reason] += 1
                    else:
                        severities = frozenset(item.severity[0].upper() for item in record.advisories)
                    provenance = [record.status, record.reason, record.response_sha256,
                                  [(a.identifier, a.severity, a.vulnerable_range) for a in record.advisories]]
            facts[name, version] = WorkspaceHealthFact(lag_ok, severities)
            manifest = meta.get("versions", {}).get(version, {})
            manifest = manifest if isinstance(manifest, dict) else {}
            rows.append([name, version, latest, observed.isoformat() if observed else None,
                         latest_date.isoformat() if latest_date else None, lag_ok,
                         sorted(severities) if severities is not None else None,
                         {key: manifest.get(key) for key in ("name", "version", "peerDependencies",
                                                              "peerDependenciesMeta", "engines", "dist")}])
            if provenance is not None:
                rows[-1].append(provenance)
    registry_digest = sha256(client.registry.encode("utf-8")).hexdigest()
    snapshot = [registry_digest, rows] if registry_advisory_source is None else [registry_digest, rows, REGISTRY_BULK_ADVISORY]
    encoded = json.dumps(snapshot, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("ascii")
    evidence = {
        "status": "COLLECTED",
        "source": REGISTRY_BULK_ADVISORY if registry_advisory_source is not None else "CORE_REGISTRY_AND_EXACT_OSV",
        "registryIdentitySha256": registry_digest,
        "lagWindowMonths": lag_months,
        "lagReference": ("LATEST_ALLOWED_REGISTRY_METADATA" if getattr(client, "draft", False) else
                         "LATEST_INSTALLABLE_IN_CONFIGURED_REGISTRY"),
        "exactVersionCount": len(facts),
        "unknownLagVersionCount": sum(fact.lag_ok is None for fact in facts.values()),
        "unknownSecurityVersionCount": sum(fact.severities is None for fact in facts.values()),
        "osvSkippedNameCount": skipped_names,
        "snapshotSha256": sha256(encoded).hexdigest(),
    }
    if registry_advisory_source is not None:
        evidence.update(registryAdvisoryUnknownReasons=dict(sorted(unknown_reasons.items())),
                        registryAdvisoryResponseSha256=sorted(response_digests))
    return facts, evidence


def workspace_registry_health_versions(packages, declarations, admitted_versions, exact_targets):
    """Build the registry version inventory from all actual non-link declarations."""
    from resolution_inventory import npm_lock_resolved_instance

    result = defaultdict(set)
    for key in declarations:
        owner, _, name = key
        installed = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
        if installed is None:
            raise ValueError("WORKSPACE_HEALTH_LOCK_INSTANCE_UNAVAILABLE")
        slot, current = installed
        if packages[slot].get("link"):
            continue
        if key in exact_targets:
            result[name].add(exact_targets[key])
        else:
            result[name].update(admitted_versions.get(key, (current,)))
    return dict(result)
