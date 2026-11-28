"""Conservative, bounded registry candidate rejection evidence (Core issue #3).

The existing LiveDataClient.registry_artifact_url_allowed remains the only
source of an admission verdict. This module CLASSIFIES already-rejected URLs;
it never normalizes a foreign URL into an allowed one, fetches from the network,
or claims that a structurally accepted package can be installed.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import unquote, urlsplit
import re


MAX_SAMPLES = 4
REJECTION_CODES = frozenset({
    "MISSING_DIST_TARBALL", "FOREIGN_TARBALL_ORIGIN", "BAD_REGISTRY_PATH",
    "HTTP_ARTIFACT_UNAVAILABLE",
})


# Display only conventional registry path labels, never arbitrary tenant IDs,
# token-like values or decoded URL parameters. The exact registry is already
# present in the caller's local configuration; diagnostics are not a URL log.
_PUBLIC_PATH_LABELS = frozenset({
    "repository", "repositories", "registry", "npm", "npm-group", "npm-hosted",
    "public", "private", "api", "v1", "v2", "artifactory", "packages",
})
# Diagnostic examples are untrusted packument keys, not a URL or token log.
_SAFE_SAMPLE_VERSION = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]{1,32})?(?:\+[0-9A-Za-z.-]{1,24})?$"
)
_SECRET_SAMPLE = re.compile(r"(?i)token|api[-_]?key|secret|password|bearer|credential")
# Never expose an unexpected status string from an untrusted/mutated probe cache.
_KNOWN_PROBE_STATUSES = frozenset({
    "available", "missing-artifact", "empty-artifact", "foreign-registry-redirect",
    "planning-only", "current-installed", "missing-tarball-url", "foreign-registry-url",
    "redirect-limit-exceeded", "unknown",
})


def _decoded_segments(path: str) -> list[str] | None:
    """Reject URL paths whose HTTP normalization can escape a registry prefix.

    Reject dot-segments at *any* finite percent-decoding depth, encoded path
    separators, invalid percent escapes, backslashes, controls and double
    slashes. The exact raw URL remains the URL used by the unchanged requests
    client; this only rules out unsafe aliases before the allowlist comparison.
    """
    if not isinstance(path, str) or not path.startswith("/") or "\\" in path:
        return None
    if path == "/":
        return []
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        return None
    if "//" in path:
        return None
    result: list[str] = []
    for segment in path[1:].split("/"):
        if not segment:
            return None
        decoded = segment
        for _ in range(8):
            # A percent sequence that is not a full escape is ambiguous.
            if re.search(r"%(?![0-9A-Fa-f]{2})", decoded):
                return None
            updated = unquote(decoded, encoding="utf-8", errors="strict")
            if updated == decoded:
                break
            decoded = updated
        if any(ch in decoded for ch in ("/", "\\", "%")):
            return None
        if decoded in (".", "..") or any(ord(ch) < 32 or ord(ch) == 127 for ch in decoded):
            return None
        result.append(decoded)
    return result


def safe_registry_artifact_url(registry: str, artifact: str) -> bool:
    """Strict same-origin, same-path policy; no redirect or network I/O.

    Signed/query-bearing tarballs require an explicit future policy rather than
    leaking bearer credentials or silently following redirects. Invalid URLs
    and malformed ports fail closed instead of throwing during a Draft run.
    """
    if not isinstance(artifact, str) or not isinstance(registry, str):
        return False
    if (not artifact or not registry or artifact != artifact.strip()
        or registry != registry.strip() or any(ord(c) < 32 or ord(c) == 127 for c in artifact + registry)):
        return False
    try:
        base, url = urlsplit(registry), urlsplit(artifact)
        if base.scheme.lower() not in ("http", "https") or url.scheme.lower() not in ("http", "https"):
            return False
        # urlsplit removes userinfo when reporting hostname; reject it outright
        # on artifact URLs. Configured registry may carry auth separately.
        if "@" in url.netloc or not base.hostname or not url.hostname:
            return False
        if not (1 <= (base.port if base.port is not None else (443 if base.scheme == "https" else 80)) <= 65535):
            return False
        if not (1 <= (url.port if url.port is not None else (443 if url.scheme == "https" else 80)) <= 65535):
            return False
        if "?" in artifact or "#" in artifact or "?" in registry or "#" in registry:
            return False
        origin = lambda p: (p.scheme.lower(), p.hostname.lower(),
                            p.port if p.port is not None else (443 if p.scheme.lower() == "https" else 80))
        if origin(base) != origin(url):
            return False
        # A trailing slash is common for the configured Nexus endpoint.
        base_path = base.path.rstrip("/") or "/"
        artifact_path = url.path or "/"
        if _decoded_segments(base_path) is None or _decoded_segments(artifact_path) is None:
            return False
        return (artifact_path == base_path or base_path == "/" or
                artifact_path.startswith(base_path + "/"))
    except (ValueError, UnicodeError):
        return False


def _identity(url: str) -> dict[str, Any]:
    """Provide only a bounded, non-secret *display* of the registry identity."""
    try:
        parts = urlsplit(str(url or ""))
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        port = parts.port if parts.port is not None else (
            443 if scheme == "https" else 80 if scheme == "http" else None
        )
    except ValueError:
        return {"origin": None, "pathPrefix": None}
    if (scheme not in {"http", "https"} or not host or port is None
        or not 1 <= port <= 65535 or
        not re.fullmatch(r"[a-zA-Z0-9.:_-]{1,253}", host)):
        return {"origin": None, "pathPrefix": None}
    printable_host = f"[{host}]" if ":" in host else host
    origin = f"{scheme}://{printable_host}"
    if port != (443 if scheme == "https" else 80):
        origin += f":{port}"
    # Never copy unknown path segments: even short, innocent-looking parts
    # may be passwords, bearer tokens or tenant IDs. Percent escapes are opaque.
    segments = parts.path.strip("/").split("/") if parts.path.strip("/") else []
    prefix = "/" + "/".join(
        x.lower() if x.lower() in _PUBLIC_PATH_LABELS else "[redacted]"
        for x in segments[:12] if x
    )
    return {"origin": origin, "pathPrefix": prefix if len(prefix) <= 160 else prefix[:148] + "[redacted]"}


def _reason_for_rejected_url(registry: str, tarball: str) -> str:
    """Classify only *after* the Core origin/path guard rejects a URL."""
    if not tarball:
        return "MISSING_DIST_TARBALL"
    registry_identity = _identity(registry)
    target_identity = _identity(tarball)
    if target_identity["origin"] is None:
        return "BAD_REGISTRY_PATH"
    if target_identity["origin"] != registry_identity["origin"]:
        return "FOREIGN_TARBALL_ORIGIN"
    return "BAD_REGISTRY_PATH"


def summarize_structural_candidates(
    registry: str,
    metadata: Mapping[str, Any],
    versions: Iterable[str],
    is_allowed: Callable[[str], bool],
    *,
    current: str = "",
) -> dict[str, Any]:
    """Explain the exact version list examined by the existing planning loop.

    Calling is_allowed delegates every admission decision to the existing
    guarded Core predicate. The returned dictionary contains no tarball URL,
    authorization header or credentials.
    """
    reasons: Counter[str] = Counter()
    samples: list[dict[str, str]] = []
    foreign_origins: list[str] = []
    seen: set[str] = set()
    totals = {"examined": 0, "accepted": 0, "rejected": 0,
              "upgradeCandidates": 0, "acceptedUpgradeCandidates": 0,
              "rejectedUpgradeCandidates": 0}
    published = metadata.get("versions") or {}
    if not isinstance(published, dict):
        published = {}
    for raw_version in versions:
        version = str(raw_version)
        totals["examined"] += 1
        if version != str(current):
            totals["upgradeCandidates"] += 1
        details = published.get(version)
        dist = details.get("dist") if isinstance(details, dict) else None
        tarball = str(dist.get("tarball") or "").strip() if isinstance(dist, dict) else ""
        if tarball and is_allowed(tarball):
            totals["accepted"] += 1
            if version != str(current):
                totals["acceptedUpgradeCandidates"] += 1
            continue
        code = _reason_for_rejected_url(registry, tarball)
        reasons[code] += 1
        totals["rejected"] += 1
        if version != str(current):
            totals["rejectedUpgradeCandidates"] += 1
        if (len(samples) < MAX_SAMPLES and len(version) <= 64
                and _SAFE_SAMPLE_VERSION.fullmatch(version)
                and not _SECRET_SAMPLE.search(version)):
            samples.append({"version": version, "code": code})
        if code == "FOREIGN_TARBALL_ORIGIN":
            origin = _identity(tarball).get("origin")
            if origin and origin not in seen:
                seen.add(origin)
                if len(foreign_origins) < MAX_SAMPLES:
                    foreign_origins.append(origin)
    all_upgrades_rejected = bool(
        totals["upgradeCandidates"] > 0
        and totals["acceptedUpgradeCandidates"] == 0
        and totals["rejectedUpgradeCandidates"] == totals["upgradeCandidates"]
    )
    return {
        "schemaVersion": 1,
        "authority": "STRUCTURAL_REGISTRY_EVIDENCE_ONLY",
        "configuredRegistry": _identity(registry),
        "metadataRequestBase": _identity(registry),
        "metadataRequestBaseAuthority": "CONFIGURATION_NOT_HTTP_TRACE",
        **totals,
        "rejectionCounts": {k: reasons[k] for k in sorted(reasons)},
        "rejectionSamples": samples,
        "rejectedArtifactOrigins": foreign_origins,
        "allUpgradeCandidatesRejected": all_upgrades_rejected,
        "physicalProbe": {"observed": 0, "failureCounts": {}, "unprobed": True},
    }


def with_observed_physical_probes(
    structural: Mapping[str, Any],
    observed: Mapping[str, Mapping[str, Any]],
    *,
    current: str = "",
) -> dict[str, Any]:
    """Add only already-performed Core probes, never trigger extra network IO."""
    report = dict(structural)
    counts: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    for version, evidence in observed.items():
        if str(version) == str(current) or not isinstance(evidence, Mapping):
            continue
        raw_state = evidence.get("status")
        state = raw_state if type(raw_state) is str and raw_state in _KNOWN_PROBE_STATUSES else "unknown"
        counts[state] += 1
        if state in {"missing-artifact", "empty-artifact"}:
            failures["HTTP_ARTIFACT_UNAVAILABLE"] += 1
        elif state == "foreign-registry-redirect":
            failures["FOREIGN_TARBALL_ORIGIN"] += 1
    # Planning-only is evidence of a known URL, NOT physical availability.
    report["physicalProbe"] = {
        "observed": sum(counts.values()),
        "statusCounts": {k: counts[k] for k in sorted(counts)},
        "failureCounts": {k: failures[k] for k in sorted(failures)},
        "unprobed": not any(k not in {"planning-only", "current-installed"} for k in counts),
    }
    return report


def no_target_diagnostic_code(status: str, evidence: Mapping[str, Any]) -> str | None:
    """Explain a NO_TARGET only with complete, self-consistent structural evidence.

    A caller-provided allUpgradeCandidatesRejected flag is NOT a proof by
    itself. Never change the solver status, and never confuse a truncated
    candidate search with global artifact unavailability.
    """
    if status == "candidate-search-truncated":
        return "CANDIDATE_CAP"
    if status != "no-target" or not isinstance(evidence, Mapping):
        return None
    fields = ("examined", "accepted", "rejected", "upgradeCandidates",
              "acceptedUpgradeCandidates", "rejectedUpgradeCandidates")
    if any(type(evidence.get(key)) is not int or not 0 <= evidence[key] <= 2_147_483_647
           for key in fields):
        return None
    examined, accepted, rejected = (evidence[key] for key in fields[:3])
    upgrades, accepted_upgrades, rejected_upgrades = (evidence[key] for key in fields[3:])
    if (accepted + rejected != examined or accepted_upgrades + rejected_upgrades != upgrades
        or upgrades > examined or accepted_upgrades > accepted or rejected_upgrades > rejected):
        return None
    reasons = evidence.get("rejectionCounts")
    if (not isinstance(reasons, Mapping)
        or any(type(k) is not str or k not in REJECTION_CODES
               or type(v) is not int or not 0 <= v <= 2_147_483_647
               for k, v in reasons.items())
        or sum(reasons.values()) != rejected):
        return None
    expected_all_rejected = upgrades > 0 and accepted_upgrades == 0 and rejected_upgrades == upgrades
    if (type(evidence.get("allUpgradeCandidatesRejected")) is not bool
        or evidence["allUpgradeCandidatesRejected"] != expected_all_rejected):
        return None
    if expected_all_rejected:
        return "NO_INSTALLABLE_ARTIFACT"
    if upgrades == 0:
        return "NO_PUBLISHED_UPGRADE_CANDIDATE"
    return "UNRESOLVED_TARGET_CONSTRAINT_OR_POLICY"

def registry_packument_error(data: Any, *, expected_name: str | None = None) -> str:
    """Return a fixed diagnostic for malformed or contradictory metadata.

    A legitimate empty version set is not a proof of installability. Missing
    optional identity/dist/tags/time fields remain permitted. When a requested
    name is supplied, explicit root/manifest names and manifest versions must
    agree with that name and their version key. Never echo untrusted values in
    the diagnostic: callers may publish it as an UNKNOWN reason.
    """
    if not isinstance(data, dict):
        return "REGISTRY_METADATA_INVALID"
    versions = data.get("versions")
    if not isinstance(versions, dict):
        return "REGISTRY_METADATA_INVALID"
    tags = data.get("dist-tags", {})
    times = data.get("time", {})
    if not isinstance(tags, dict) or not isinstance(times, dict):
        return "REGISTRY_METADATA_INVALID"
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in tags.items()):
        return "REGISTRY_METADATA_INVALID"
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in times.items()):
        return "REGISTRY_METADATA_INVALID"
    if expected_name is not None and "name" in data and data["name"] != expected_name:
        return "REGISTRY_PACKAGE_IDENTITY_MISMATCH"
    for key, value in versions.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            return "REGISTRY_METADATA_INVALID"
        if expected_name is not None:
            if "name" in value and value["name"] != expected_name:
                return "REGISTRY_PACKAGE_IDENTITY_MISMATCH"
            if "version" in value and value["version"] != key:
                return "REGISTRY_VERSION_IDENTITY_MISMATCH"
        dist = value.get("dist")
        if dist is not None:
            if not isinstance(dist, dict):
                return "REGISTRY_METADATA_INVALID"
            tarball = dist.get("tarball")
            if tarball is not None and not isinstance(tarball, str):
                return "REGISTRY_METADATA_INVALID"
    return ""


def valid_registry_packument_shape(data: Any, *, expected_name: str | None = None) -> bool:
    """Validate structure, and optional requested identity, before reuse."""
    return not registry_packument_error(data, expected_name=expected_name)
