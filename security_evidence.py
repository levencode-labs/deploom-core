"""Bounded OSV validation and conservative severity evidence for planning.

An unrated finding is still a finding. It cannot prove a no-Critical/no-High
goal. CVSS vectors are scored by the pinned cvss library, never by extracting a
number from untrusted text. DepLoom uses base severity (not a project's assumed
mitigations) and the highest supplied rating; an unsupported or invalid rating
keeps the assessment incomplete even when another positive rating is known.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import math
import re
from typing import Any

from cvss import CVSS2, CVSS3, CVSS4, CVSSError


_ID = re.compile(r"[A-Za-z0-9:_.-]{1,256}\Z")
_CATEGORY_RANK = {"low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}
_PARSERS = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}
_V4_BASE = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")


class InvalidOsvEvidence(ValueError):
    """Fixed diagnostic; never include untrusted response contents."""


def valid_osv_id(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _validate_severity_list(value: Any) -> None:
    if (not isinstance(value, list) or len(value) > 64
            or any(not isinstance(item, dict)
                   or not isinstance(item.get("type"), str) or not item["type"]
                   or not isinstance(item.get("score"), str) or not item["score"]
                   or len(item["type"]) > 64 or len(item["score"]) > 2048
                   or ("source" in item and not isinstance(item["source"], str))
                   for item in value)):
        raise InvalidOsvEvidence("OSV_SEVERITY_INVALID")


def validate_osv_detail(value: Any, expected_id: str | None = None) -> None:
    """Validate the identity and fields consumed by Core before caching.

    Optional fields and future extra fields remain allowed. In particular a
    missing severity is valid incomplete evidence, not a clean assessment.
    """
    if not isinstance(value, dict) or "error" in value or not valid_osv_id(value.get("id")):
        raise InvalidOsvEvidence("OSV_DETAIL_INVALID")
    if expected_id is not None and value["id"] != expected_id:
        raise InvalidOsvEvidence("OSV_DETAIL_IDENTITY_MISMATCH")
    if "database_specific" in value:
        specific = value["database_specific"]
        if (not isinstance(specific, dict)
                or ("severity" in specific and not isinstance(specific["severity"], str))):
            raise InvalidOsvEvidence("OSV_DETAIL_INVALID")
    if "severity" in value:
        _validate_severity_list(value["severity"])
    if "affected" in value:
        affected = value["affected"]
        if not isinstance(affected, list) or any(not isinstance(item, dict) for item in affected):
            raise InvalidOsvEvidence("OSV_DETAIL_INVALID")
        for item in affected:
            if "severity" in item:
                _validate_severity_list(item["severity"])
            if "package" in item:
                package = item["package"]
                if (not isinstance(package, dict)
                        or any(not isinstance(package.get(key), str) or not package[key]
                               for key in ("ecosystem", "name"))):
                    raise InvalidOsvEvidence("OSV_DETAIL_INVALID")
        if value.get("severity") and any(item.get("severity") for item in affected):
            raise InvalidOsvEvidence("OSV_SEVERITY_SCOPE_CONFLICT")


def validate_osv_entries(entries: Any) -> None:
    if not isinstance(entries, list):
        raise InvalidOsvEvidence("OSV_QUERY_INVALID")
    for entry in entries:
        validate_osv_detail(entry)


def osv_batch_references(payload: Any, expected_count: int) -> list[tuple[str, ...]]:
    """Validate the entire positional response before publishing any pairs."""
    if not isinstance(payload, dict) or "error" in payload or not isinstance(payload.get("results"), list):
        raise InvalidOsvEvidence("OSV_QUERY_INVALID")
    results = payload["results"]
    if len(results) != expected_count:
        raise InvalidOsvEvidence("OSV_QUERY_INCOMPLETE")
    references = []
    for result in results:
        if not isinstance(result, dict) or "error" in result:
            raise InvalidOsvEvidence("OSV_QUERY_INVALID")
        if ("next_page_token" in result and not isinstance(result["next_page_token"], str)):
            raise InvalidOsvEvidence("OSV_QUERY_INVALID")
        if result.get("next_page_token"):
            raise InvalidOsvEvidence("OSV_QUERY_INCOMPLETE")
        raw = result.get("vulns", [])
        if (not isinstance(raw, list)
                or any(not isinstance(ref, dict) or "error" in ref or not valid_osv_id(ref.get("id")) for ref in raw)):
            raise InvalidOsvEvidence("OSV_QUERY_INVALID")
        references.append(tuple(dict.fromkeys(ref["id"] for ref in raw)))
    return references


@dataclass(frozen=True)
class SeverityAssessment:
    rank: int | None = None
    reason: str = ""

    @property
    def complete(self) -> bool:
        return self.rank is not None and not self.reason


@lru_cache(maxsize=2048)
def _cvss_rank(kind: str, vector: str) -> int | None:
    """Cache only bounded public scoring inputs, never mutable advisory bodies."""
    parser = _PARSERS[kind]
    try:
        parsed = parser(vector)
        if parser is CVSS4:
            # Validate the full vector first, then remove optional threat /
            # environmental adjustments: Core has no project mitigation proof.
            parsed = CVSS4("CVSS:4.0/" + "/".join(f"{key}:{parsed.metrics[key]}" for key in _V4_BASE))
        score = float(parsed.scores()[0])
        if not math.isfinite(score) or not 0 <= score <= 10:
            return None
        return 4 if score >= 9 else 3 if score >= 7 else 2 if score >= 4 else 1
    except (CVSSError, ValueError, TypeError, KeyError, ArithmeticError):
        return None


def assess_severity(vuln: Any, *, package: str | None = None) -> SeverityAssessment:
    if not isinstance(vuln, dict):
        return SeverityAssessment(reason="INVALID_SEVERITY")
    specific = vuln.get("database_specific")
    category = specific.get("severity", "") if isinstance(specific, dict) else ""
    ranks = [_CATEGORY_RANK[category.lower()]] if isinstance(category, str) and category.lower() in _CATEGORY_RANK else []
    raw = vuln.get("severity", [])
    affected = vuln.get("affected", [])
    if isinstance(affected, list) and any(isinstance(item, dict) and item.get("severity") for item in affected):
        if raw:
            return SeverityAssessment(max(ranks) if ranks else None, "INVALID_SEVERITY")
        selected = [item for item in affected if isinstance(item, dict)
                    and isinstance(item.get("package"), dict)
                    and item["package"].get("ecosystem") == "npm"
                    and package is not None and item["package"].get("name") == package]
        if not selected:
            return SeverityAssessment(max(ranks) if ranks else None, "PACKAGE_SEVERITY_SCOPE_UNRESOLVED")
        raw = []
        for item in selected:
            try:
                _validate_severity_list(item.get("severity", []))
            except InvalidOsvEvidence:
                return SeverityAssessment(max(ranks) if ranks else None, "INVALID_SEVERITY")
            raw.extend(item.get("severity", []))
    try:
        _validate_severity_list(raw)
    except InvalidOsvEvidence:
        return SeverityAssessment(max(ranks) if ranks else None, "INVALID_SEVERITY")
    reason = ("UNSUPPORTED_SEVERITY_CATEGORY" if isinstance(category, str) and category
              and category.lower() not in _CATEGORY_RANK else "")
    for item in raw:
        if item["type"] not in _PARSERS:
            reason = reason or "UNSUPPORTED_SEVERITY_TYPE"
            continue
        rank = _cvss_rank(item["type"], item["score"])
        if rank is None:
            reason = reason or "INVALID_SEVERITY"
        else:
            ranks.append(rank)
    return SeverityAssessment(max(ranks) if ranks else None, reason or ("" if ranks else "MISSING_SEVERITY"))


def severity_evidence_diagnostic(entries: list[Any], *, package: str | None = None,
                                 source: str) -> dict[str, Any]:
    """Describe completeness without dropping already observed findings."""
    reasons = [item.reason for item in (assess_severity(entry, package=package) for entry in entries)
               if item.reason]
    return {
        "status": "UNKNOWN" if reasons else "ASSESSED", "source": source,
        "findingCount": len(entries), **({"reason": reasons[0]} if reasons else {}),
    }


def security_goal_satisfied(entries: Any, mode: str, *, package: str | None = None) -> bool:
    """Empty successful results and complete low ratings have distinct meaning."""
    if not isinstance(entries, list):
        return False
    try:
        validate_osv_entries(entries)
    except InvalidOsvEvidence:
        return False
    if mode == "no-vuln":
        return not entries
    threshold = {"no-critical": 4, "no-high": 3}.get(mode)
    if threshold is None:
        return False
    assessments = [assess_severity(entry, package=package) for entry in entries]
    return all(item.complete and item.rank < threshold for item in assessments)
