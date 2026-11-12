"""Compile owner-qualified npm peer constraints for an explicit provider topology.

The caller supplies finite admitted domains and candidate metadata. Provider
bindings are assumptions of the model, not a prediction of npm placement.
"""
from __future__ import annotations

import json
from hashlib import sha256
from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
from typing import Mapping

from semantic_version import NpmSpec, Version

from project_runtime import normalize_npm_range

from peer_solver_model import PackageVariable, PeerOptimizationModel, RequiresAny, forbidden
from peer_solver_z3 import solve_z3_exact
from resolution_inventory import npm_lock_resolution_slots, npm_lock_resolved_instance
from workspace_npm_lock_delta import INSTALL_SECTIONS, peer_context
from workspace_health_policy import WorkspaceHealthFact, WorkspaceHealthPolicy, solve_workspace_health

Declaration = tuple[str, str, str]


@dataclass(frozen=True)
class WorkspaceCandidate:
    version: str
    peers: Mapping[str, str]
    optional_peers: frozenset[str] = frozenset()
    engines: Mapping[str, str] = field(default_factory=dict)
    evidence_reason: str | None = None


@dataclass(frozen=True)
class WorkspaceDomain:
    current: str
    candidates: tuple[WorkspaceCandidate, ...]
    mutable: bool = False
    exact_target: str | None = None


@dataclass(frozen=True)
class LockedWorkspacePeer:
    """A registry peer version present in the observed npm lock layout."""

    version: str


@dataclass(frozen=True)
class WorkspaceTopology:
    providers: Mapping[tuple[Declaration, str], Declaration | None]
    instance_groups: tuple[tuple[Declaration, ...], ...]


class WorkspaceModelUnknown(ValueError):
    """Evidence does not suffice to compile a complete modeled domain."""


def declaration_id(declaration: Declaration) -> str:
    return json.dumps(declaration, separators=(",", ":"), ensure_ascii=True)


def workspace_providers_from_lock(
    packages: dict,
    domains: Mapping[Declaration, WorkspaceDomain],
    *,
    shared_slots: frozenset[str] = frozenset(),
) -> dict[tuple[Declaration, str], Declaration | LockedWorkspacePeer | None]:
    """Find provider variables or fixed registry versions in the observed lock.

    Follow the consumer package location, not the declaration owner's lookup.
    Declarations held at the same locked instance have the same provider version.
    Bind a mutable shared placement only when the planner will enforce one
    version across its declarations. Explicit absence is available only for a
    lock-documented optional peer with no matching slot. These bindings only
    describe this lock.
    """
    instances = {}
    by_path = {}
    for declaration, domain in domains.items():
        owner, _, name = declaration
        instance = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
        if instance is None or instance[1] != domain.current:
            continue
        path, _ = instance
        entry = packages[path]
        instances[declaration] = entry["resolved"] if entry.get("link") else path
        if not entry.get("link"):
            by_path.setdefault((path, name), []).append(declaration)

    bindings = {}
    for declaration, path in instances.items():
        for peer in sorted({name for item in domains[declaration].candidates for name in item.peers}):
            context = peer_context(path)
            instance = npm_lock_resolved_instance(packages, peer, context)
            if instance is None:
                record = packages[path]
                if (peer in record.get("peerDependencies", {})
                        and record.get("peerDependenciesMeta", {}).get(peer, {}).get("optional") is True
                        and not any(slot in packages for slot in npm_lock_resolution_slots(peer, context))):
                    bindings[declaration, peer] = None
                continue
            slot, version = instance
            matches = by_path.get((slot, peer), ())
            if matches and (len(matches) == 1 or slot in shared_slots
                            or all(not domains[key].mutable for key in matches)):
                bindings[declaration, peer] = min(matches)
            elif not matches:
                record = packages[slot]
                resolved, integrity = record.get("resolved"), record.get("integrity")
                if (not record.get("link") and record.get("name", peer) == peer
                        and isinstance(resolved, str) and resolved.startswith("https://")
                        and isinstance(integrity, str) and integrity):
                    bindings[declaration, peer] = LockedWorkspacePeer(version)
    return bindings


def _workspace_owner_peer_rows(packages):
    """Read root and linked-owner contracts from the supplied lock snapshot.

    MCP binds these records to current manifest bytes before calling Core.
    Direct Core callers receive a verdict conditional on their lock evidence.
    Peers shadowed by installed edges follow the native npm preflight semantics.
    """
    links = {row["resolved"] for row in packages.values()
             if isinstance(row, dict) and row.get("link") is True
             and isinstance(row.get("resolved"), str)}
    rows = []
    for owner, record in sorted(packages.items()):
        if "node_modules" in owner.split("/"):
            continue
        if not isinstance(record, dict):
            raise WorkspaceModelUnknown(f"OWNER_MANIFEST_UNPROVEN: {owner}")
        peers = record.get("peerDependencies", {})
        meta = record.get("peerDependenciesMeta", {})
        if (not isinstance(peers, dict) or not isinstance(meta, dict)
                or any(not isinstance(record.get(section, {}), dict)
                       for section in ("dependencies", "optionalDependencies"))):
            raise WorkspaceModelUnknown(f"OWNER_PEER_METADATA_UNSUPPORTED: {owner}")
        if peers and owner and owner not in links:
            raise WorkspaceModelUnknown(f"OWNER_LINK_UNPROVEN: {owner}")
        for peer, spec in sorted(peers.items()):
            if (not isinstance(peer, str) or not isinstance(spec, str)
                    or not isinstance(meta.get(peer, {}), dict)):
                raise WorkspaceModelUnknown(f"OWNER_PEER_METADATA_UNSUPPORTED: {owner}")
            if any(peer in record.get(section, {}) for section in ("dependencies", "optionalDependencies")):
                continue
            rows.append((owner, peer, spec, meta.get(peer, {}).get("optional") is True))
    return rows


def _constrain_workspace_owner_peers(model, packages, domains, effective_peer_ranges):
    """Constrain provider variables without inventing owner install declarations."""
    rows = _workspace_owner_peer_rows(packages)
    by_slot = {}
    for key, domain in domains.items():
        slot = npm_lock_resolved_instance(packages, key[2], "" if key[0] == "." else key[0])
        if slot is not None and slot[1] == domain.current:
            by_slot.setdefault(slot[0], []).append(key)
    variables = model.package_map()
    constraints = list(model.constraints)
    for owner, peer, raw, optional in rows:
        spec = (effective_peer_ranges or {}).get((owner, packages[owner].get("version"), peer, raw), raw)
        try:
            matcher = NpmSpec(normalize_npm_range(spec))
        except (ValueError, TypeError) as exc:
            raise WorkspaceModelUnknown(f"OWNER_PEER_RANGE_UNSUPPORTED: {owner} -> {peer}: {spec}") from exc
        nearest = next((slot for slot in npm_lock_resolution_slots(peer, owner) if slot in packages), None)
        resolved = npm_lock_resolved_instance(packages, peer, owner)
        if resolved is None or resolved[0] != nearest:
            if optional and nearest is None:
                continue
            raise WorkspaceModelUnknown(f"OWNER_PEER_PROVIDER_UNPROVEN: {owner} -> {peer}")
        slot, current = resolved
        try:
            current_version = Version(current)
        except (ValueError, TypeError) as exc:
            raise WorkspaceModelUnknown(f"OWNER_PEER_PROVIDER_UNPROVEN: {owner} -> {peer}") from exc
        keys = by_slot.get(slot, ())
        reason = f"workspace owner {owner or '.'} requires {peer}@{spec}"
        if keys:
            for key in keys:
                variable = variables[declaration_id(key)]
                for version in variable.domain:
                    if not matcher.match(Version(version)):
                        constraints.append(forbidden(((variable.name, version),), reason=reason,
                                                     provenance="workspace-owner-peer"))
        else:
            record = packages[slot]
            if (record.get("link") or record.get("name", peer) != peer
                    or not isinstance(record.get("resolved"), str)
                    or not record["resolved"].startswith("https://")
                    or not isinstance(record.get("integrity"), str) or not record["integrity"]):
                raise WorkspaceModelUnknown(f"OWNER_PEER_PROVIDER_UNPROVEN: {owner} -> {peer}")
            if not matcher.match(current_version):
                # An immutable external provider violates the owner contract for
                # every assignment; block each literal of an existing variable.
                variable = model.packages[0]
                constraints.extend(forbidden(((variable.name, version),), reason=reason,
                                             provenance="workspace-owner-peer") for version in variable.domain)
    return replace(model, constraints=tuple(constraints)), len(rows)


def _selected_candidates(domain: WorkspaceDomain) -> tuple[WorkspaceCandidate, ...]:
    return tuple(candidate for candidate in domain.candidates
                 if (domain.mutable or candidate.version == domain.current)
                 and (domain.exact_target is None or candidate.version == domain.exact_target))


def compile_workspace_peer_model(
    domains: Mapping[Declaration, WorkspaceDomain],
    providers: Mapping[tuple[Declaration, str], Declaration | LockedWorkspacePeer | None],
    *,
    environment: Mapping[str, str] | None = None,
    unknown_candidates: list[dict] | None = None,
) -> PeerOptimizationModel:
    """Build existing solver IR, failing closed for absent provider evidence.

    A missing binding is unknown. An explicit None represents absence in the
    modeled topology and only satisfies an optional peer. When an evidence
    collector is supplied, unknown candidate literals are blocked in the proven
    submodel and reported without shrinking domains or changing preferences.
    """
    selected = {}
    variables = []
    for key, domain in sorted(domains.items()):
        if domain.exact_target is not None and not domain.mutable and domain.exact_target != domain.current:
            raise ValueError(f"EXACT_TARGET_OUTSIDE_AUTHORITY: {key}")
        candidates = _selected_candidates(domain)
        versions = tuple(candidate.version for candidate in candidates)
        if not versions:
            raise WorkspaceModelUnknown(f"CANDIDATE_EVIDENCE_MISSING: {key}")
        if len(set(versions)) != len(versions):
            raise ValueError(f"DUPLICATE_CANDIDATE: {key}")
        selected[key] = candidates
        # Primary objective minimizes changed declarations. Candidate order
        # supplied by the caller determines preference among equal-change plans.
        scores = tuple((version, (int(version == domain.current), -rank))
                       for rank, version in enumerate(versions))
        variables.append(PackageVariable(declaration_id(key), domain.current, versions, scores))

    requirements = []
    forbidden_constraints = []
    for key, candidates in selected.items():
        for candidate in candidates:
            trigger = (declaration_id(key), candidate.version)
            try:
                if candidate.evidence_reason:
                    raise WorkspaceModelUnknown(candidate.evidence_reason)
                for engine, spec in sorted(candidate.engines.items()):
                    if engine not in {"node", "npm"}:
                        continue
                    if environment is None or engine not in environment:
                        raise WorkspaceModelUnknown(f"ENGINE_VERSION_UNKNOWN: {key} -> {engine}")
                    try:
                        matches = NpmSpec(normalize_npm_range(spec)).match(Version(environment[engine]))
                    except ValueError as exc:
                        raise WorkspaceModelUnknown(f"ENGINE_RANGE_UNSUPPORTED: {key} -> {engine}: {spec}") from exc
                    if not matches:
                        forbidden_constraints.append(forbidden(
                            (trigger,), reason=f"{key}@{candidate.version} requires {engine}@{spec}",
                            provenance="workspace-modeled-engine-range",
                        ))
                for peer, spec in sorted(candidate.peers.items()):
                    binding = (key, peer)
                    if binding not in providers:
                        raise WorkspaceModelUnknown(f"PEER_PROVIDER_UNKNOWN: {key}@{candidate.version} -> {peer}")
                    provider = providers[binding]
                    if isinstance(provider, LockedWorkspacePeer):
                        try:
                            matches = NpmSpec(normalize_npm_range(spec)).match(Version(provider.version))
                        except ValueError as exc:
                            raise WorkspaceModelUnknown(f"PEER_RANGE_UNSUPPORTED: {key} -> {peer}: {spec}") from exc
                        if not matches:
                            forbidden_constraints.append(forbidden(
                                (trigger,), reason=f"{key}@{candidate.version} requires {peer}@{spec}; "
                                                  f"observed transitive version is {provider.version}",
                                provenance="workspace-observed-transitive-peer",
                            ))
                        continue
                    if provider is None:
                        if peer in candidate.optional_peers:
                            continue
                        # An empty requirement against the trigger's own variable
                        # makes this exact candidate infeasible.
                        provider, allowed = key, ()
                    else:
                        if provider not in selected:
                            raise WorkspaceModelUnknown(f"PEER_PROVIDER_OUTSIDE_MODEL: {key} -> {peer}")
                        if provider[2] != peer:
                            raise ValueError(f"PEER_PROVIDER_NAME_MISMATCH: {key} -> {peer}")
                        try:
                            npm_range = NpmSpec(normalize_npm_range(spec))
                            allowed = tuple(item.version for item in selected[provider]
                                            if npm_range.match(Version(item.version)))
                        except ValueError as exc:
                            raise WorkspaceModelUnknown(f"PEER_RANGE_UNSUPPORTED: {key} -> {peer}: {spec}") from exc
                    requirements.append(RequiresAny(
                        trigger, declaration_id(provider), allowed,
                        reason=f"{key}@{candidate.version} requires {peer}@{spec} via {provider}",
                        provenance="workspace-modeled-peer-range",
                    ))
            except WorkspaceModelUnknown as exc:
                if unknown_candidates is None:
                    raise
                unknown_candidates.append({
                    "owner": key[0], "section": key[1], "name": key[2],
                    "version": candidate.version, "reason": str(exc),
                })
                # Keep original domains/ranks and all variables. Only this
                # evidence-deficient literal is unavailable in the proven model.
                forbidden_constraints.append(forbidden(
                    (trigger,), reason=str(exc), provenance="workspace-candidate-evidence-unknown",
                ))
    return PeerOptimizationModel(tuple(variables), constraints=tuple(forbidden_constraints),
                                 requirements=tuple(requirements), objective_width=2)


def workspace_domains_from_inputs(
    packages: dict,
    declarations: Mapping[Declaration, str],
    admitted_versions: Mapping[Declaration, tuple[str, ...]],
    exact_targets: Mapping[Declaration, str],
    packuments: Mapping[str, dict],
    *,
    allow_partial: bool = False,
) -> dict[Declaration, WorkspaceDomain]:
    """Bind admitted candidate metadata and lock versions to declaration owners.

    Only keys explicitly admitted by the caller are mutable. Candidate lists
    must have passed registry origin, stability and version-line policy upstream.
    """
    if not admitted_versions.keys() <= declarations.keys() or not exact_targets.keys() <= admitted_versions.keys():
        raise ValueError("EXACT_OR_MUTABLE_TARGET_OUTSIDE_DECLARATIONS")
    domains = {}
    for key in declarations:
        owner, _, name = key
        current = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
        if current is None:
            raise WorkspaceModelUnknown(f"WORKSPACE_SLOT_UNPROVEN: {key}")
        path, version = current
        mutable = key in admitted_versions
        choices = admitted_versions.get(key, (version,))
        exact = exact_targets.get(key)
        if exact is not None and exact not in choices:
            raise ValueError(f"EXACT_TARGET_OUTSIDE_ADMITTED_DOMAIN: {key}")
        entry = packages[path]
        if entry.get("link"):
            if mutable:
                raise ValueError(f"WORKSPACE_LINK_TARGET_NOT_MUTABLE: {key}")
            metadata = {version: packages[entry["resolved"]]}
        else:
            metadata = packuments.get(name, {}).get("versions", {})

        candidates = []
        for choice in choices:
            try:
                item = metadata.get(choice)
                if not isinstance(item, dict) or item.get("version") != choice:
                    raise WorkspaceModelUnknown(f"CANDIDATE_METADATA_MISSING: {key}@{choice}")
                if not entry.get("link") and item.get("name") != name:
                    raise WorkspaceModelUnknown(f"CANDIDATE_METADATA_IDENTITY_MISMATCH: {key}@{choice}")
                peers = item.get("peerDependencies", {})
                peer_meta = item.get("peerDependenciesMeta", {})
                engines = item.get("engines", {})
                if (not all(isinstance(value, dict) for value in (peers, peer_meta, engines))
                        or any(not isinstance(value, str) for value in (*peers.values(), *engines.values()))
                        or any(not isinstance(value, dict) for value in peer_meta.values())):
                    raise WorkspaceModelUnknown(f"CANDIDATE_METADATA_INVALID: {key}@{choice}")
                optional = frozenset(peer for peer, flags in peer_meta.items() if flags.get("optional") is True)
                candidates.append(WorkspaceCandidate(choice, peers, optional, engines))
            except WorkspaceModelUnknown as exc:
                if not allow_partial:
                    raise
                candidates.append(WorkspaceCandidate(choice, {}, evidence_reason=str(exc)))
        domains[key] = WorkspaceDomain(version, tuple(candidates), mutable, exact)
    return domains


def _project_single_nested_slot(packages, domains, keys):
    """Project one exact owner's lookup while retaining every held lock edge."""
    mutable = [key for key, domain in domains.items() if domain.mutable]
    if len(mutable) != 1 or mutable[0] not in keys:
        return None
    target = mutable[0]
    owner, section, name = target
    domain = domains[target]
    if (owner == "." or section not in INSTALL_SECTIONS or domain.exact_target in (None, domain.current)
            or not any(row.get("link") is True and row.get("resolved") == owner for row in packages.values())):
        return None
    slot = f"{owner}/node_modules/{name}"
    if any(path == slot or path.startswith(slot + "/") for path in packages):
        return None

    # This record is a lookup placeholder for a model variable. It has no
    # package identity or peer metadata beyond the candidate's registry evidence.
    projected = {**packages, slot: {"version": domain.current}}
    for key in domains:
        context = "" if key[0] == "." else key[0]
        expected = (slot, domain.current) if key == target else npm_lock_resolved_instance(packages, key[2], context)
        if npm_lock_resolved_instance(projected, key[2], context) != expected:
            return None

    for path, row in packages.items():
        if not (path == owner or path.startswith(owner + "/")):
            continue
        for edge_section in (*INSTALL_SECTIONS, "peerDependencies"):
            if (path, edge_section, name) == target or name not in row.get(edge_section, {}):
                continue
            context = peer_context(path) if edge_section == "peerDependencies" else path
            if npm_lock_resolved_instance(projected, name, context) != npm_lock_resolved_instance(packages, name, context):
                return None

    # A held candidate can have registry peer metadata absent from its lock row.
    for key, held in domains.items():
        if key == target or not any(name in candidate.peers for candidate in held.candidates):
            continue
        instance, _ = npm_lock_resolved_instance(packages, key[2], "" if key[0] == "." else key[0])
        entry = packages[instance]
        context = peer_context(entry["resolved"] if entry.get("link") else instance)
        if npm_lock_resolved_instance(projected, name, context) != npm_lock_resolved_instance(packages, name, context):
            return None
    return projected, slot


def _constrain_shared_instances(model, groups, *, provenance):
    variables = model.package_map()
    requirements = list(model.requirements)
    for group in groups:
        first, *others = sorted(map(declaration_id, group))
        for other in others:
            for version in variables[first].domain:
                allowed = (version,) if version in variables[other].domain else ()
                requirements.append(RequiresAny(
                    (first, version), other, allowed,
                    reason=f"{first} and {other} share one npm instance", provenance=provenance,
                ))
    return replace(model, requirements=tuple(requirements))


def plan_workspace_from_lock(
    packages: dict,
    domains: Mapping[Declaration, WorkspaceDomain],
    *,
    environment: Mapping[str, str] | None = None,
    timeout_ms: int = 30_000,
    excluded_assignments: tuple[Mapping[str, str], ...] = (),
    include_constraint_evidence: bool = False,
    health_solver=None,
    effective_peer_ranges: Mapping[tuple[str, str, str, str], str] | None = None,
    prepare_only: bool = False,
    propose_nested_slot: bool = False,
) -> dict | PreparedWorkspacePlan:
    """Plan under observed slots or one guarded, hypothetical nested slot."""
    result = {"authority": "PLANNING_ONLY", "verification": "NOT_VERIFIED",
              "topology": "OBSERVED_LOCK_LAYOUT", "assignment": None}
    try:
        if not domains:
            raise WorkspaceModelUnknown("WORKSPACE_DOMAIN_EMPTY")
        instances = {}
        for key, domain in domains.items():
            owner, _, name = key
            instance = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
            if instance is None or instance[1] != domain.current or (domain.mutable and packages[instance[0]].get("link")):
                raise WorkspaceModelUnknown(f"WORKSPACE_SLOT_UNPROVEN: {key}")
            instances.setdefault(instance[0], []).append(key)
        if effective_peer_ranges:
            domains = dict(domains)
            for path, keys in instances.items():
                for key in keys:
                    domain = domains[key]
                    if domain.mutable or packages[path].get("link"):
                        continue
                    candidates = tuple(
                        replace(candidate, peers={
                            peer: effective_peer_ranges.get((path, candidate.version, peer, spec), spec)
                            for peer, spec in candidate.peers.items()
                        }) if candidate.version == domain.current else candidate
                        for candidate in domain.candidates
                    )
                    domains[key] = replace(domain, candidates=candidates)
        shared_slots = frozenset(
            path for path, keys in instances.items()
            if len(keys) > 1 and len({
                frozenset(candidate.version for candidate in _selected_candidates(domains[key]))
                for key in keys
            }) == 1
        )
        unknown_candidates = []
        model = compile_workspace_peer_model(
            domains, workspace_providers_from_lock(packages, domains, shared_slots=shared_slots),
            environment=environment, unknown_candidates=unknown_candidates)
        model, owner_peer_count = _constrain_workspace_owner_peers(
            model, packages, domains, effective_peer_ranges)
        result["ownerPeerConstraintCount"] = owner_peer_count
        result["domain"] = _domain_evidence(model, unknown_candidates)
        variables = model.package_map()
        unproven = {(row["owner"], row["section"], row["name"]) for row in unknown_candidates}
        shared = []
        for path, keys in instances.items():
            if len(keys) == 1:
                continue
            if path in shared_slots:
                if len(variables[declaration_id(keys[0])].domain) == 1:
                    continue
                if unproven.isdisjoint(keys):
                    shared.append(keys)
                    continue
            if propose_nested_slot and not effective_peer_ranges and health_solver is None:
                projection = _project_single_nested_slot(packages, domains, keys)
                if projection is not None:
                    projected, slot = projection
                    prepared = plan_workspace_from_lock(
                        projected, domains, environment=environment, prepare_only=True,
                        include_constraint_evidence=include_constraint_evidence,
                    )
                    if (isinstance(prepared, PreparedWorkspacePlan)
                            and prepared.result["domain"]["evidenceCoverage"] == "COMPLETE"):
                        prepared = replace(prepared, result={
                            **prepared.result, "topology": "PROPOSED_INSTANCE_LAYOUT",
                            "proposedNestedSlot": slot,
                        })
                        return prepared if prepare_only else prepared.solve(
                            excluded_assignments, timeout_ms=timeout_ms)
            raise WorkspaceModelUnknown(f"SHARED_SLOT_RELAYOUT_UNMODELED: {path}")
        if shared:
            model = _constrain_shared_instances(model, shared, provenance="workspace-observed-instance")
    except WorkspaceModelUnknown as exc:
        return {**result, "status": "UNKNOWN", "reason": str(exc)}

    prepared = PreparedWorkspacePlan(
        model, deepcopy(result),
        _constraint_evidence(model, domains) if include_constraint_evidence else None, health_solver,
    )
    return prepared if prepare_only else prepared.solve(excluded_assignments, timeout_ms=timeout_ms)


def plan_workspace_in_topology(
    domains: Mapping[Declaration, WorkspaceDomain],
    providers: Mapping[tuple[Declaration, str], Declaration | None],
    instance_groups: tuple[tuple[Declaration, ...], ...],
    *,
    environment: Mapping[str, str] | None = None,
    timeout_ms: int = 30_000,
    excluded_assignments: tuple[Mapping[str, str], ...] = (),
    include_constraint_evidence: bool = False,
    health_solver=None,
    prepare_only: bool = False,
) -> dict | PreparedWorkspacePlan:
    """Check a proposed partition into npm instances before native resolution."""
    result = {"authority": "PLANNING_ONLY", "verification": "NOT_VERIFIED",
              "topology": "PROPOSED_INSTANCE_LAYOUT", "assignment": None}
    members = [key for group in instance_groups for key in group]
    if (not domains or set(members) != domains.keys() or len(members) != len(domains)
            or any(not group or len({key[2] for key in group}) != 1 for group in instance_groups)):
        return {**result, "status": "UNKNOWN", "reason": "WORKSPACE_INSTANCE_PARTITION_UNPROVEN"}
    try:
        unknown_candidates = []
        model = compile_workspace_peer_model(domains, providers, environment=environment,
                                             unknown_candidates=unknown_candidates)
        result["domain"] = _domain_evidence(model, unknown_candidates)
    except WorkspaceModelUnknown as exc:
        return {**result, "status": "UNKNOWN", "reason": str(exc)}

    model = _constrain_shared_instances(model, instance_groups, provenance="workspace-proposed-instance")
    prepared = PreparedWorkspacePlan(
        model, deepcopy(result),
        _constraint_evidence(model, domains) if include_constraint_evidence else None, health_solver,
    )
    return prepared if prepare_only else prepared.solve(excluded_assignments, timeout_ms=timeout_ms)


def _constraint_evidence(model, domains):
    """Capture compiled static rules touching mutable declarations, before retry exclusions."""
    scope = {declaration_id(key) for key, domain in domains.items() if domain.mutable}
    rules = []
    total = 0
    for requirement in model.requirements:
        consumer, version = requirement.trigger
        if consumer not in scope and requirement.provider not in scope:
            continue
        total += 1
        if len(rules) < 128:
            rules.append({
                "consumer": consumer, "version": version, "provider": requirement.provider,
                "allowedVersions": list(requirement.allowed_versions),
                "provenance": requirement.provenance,
            })
    for clause in model.constraints:
        if clause.provenance not in {"workspace-modeled-engine-range", "workspace-observed-transitive-peer", "workspace-owner-peer"}:
            continue
        consumer, version = clause.literals[0]
        if consumer not in scope:
            continue
        total += 1
        if len(rules) < 128:
            rules.append({"consumer": consumer, "version": version, "provider": None,
                          "allowedVersions": [], "provenance": clause.provenance})
    return {"domains": {package.name: list(package.domain) for package in model.packages if package.name in scope},
            "rules": rules, "ruleCount": total}


@dataclass(frozen=True)
class PreparedWorkspacePlan:
    """Request-local static model and evidence; solving never performs I/O.

    Exclusions are supplied per search, never retained or promoted to peer rules.
    Returned dictionaries are independent of the prepared snapshot.
    """

    model: PeerOptimizationModel | None
    result: dict
    constraint_evidence: dict | None = None
    health_solver: object = None
    policy_evidence: dict | None = None

    def solve(self, excluded_assignments=(), *, timeout_ms=30_000):
        if self.model is None:
            return deepcopy(self.result)
        result = _solve_workspace_model(
            self.model, deepcopy(self.result), timeout_ms, tuple(excluded_assignments),
            deepcopy(self.constraint_evidence), self.health_solver,
        )
        if "proposedNestedSlot" in result and result["status"] == "UNSAT_IN_MODELED_DOMAIN":
            result.update(status="UNKNOWN", reason="PROPOSED_NESTED_SLOT_HAS_NO_WITNESS", optimality="NOT_PROVEN")
        if self.policy_evidence is not None:
            result["policy"]["evidence"] = deepcopy(self.policy_evidence)
        return result


def prepare_workspace_from_registry(*args, **kwargs) -> PreparedWorkspacePlan:
    """Collect and compile once, without solving or retaining a live client."""
    if "prepare_only" in kwargs or kwargs.get("excluded_assignments"):
        raise ValueError("PREPARED_WORKSPACE_EXCLUDES_SEARCH_STATE")
    prepared = plan_workspace_from_registry(*args, **kwargs, prepare_only=True)
    return prepared if isinstance(prepared, PreparedWorkspacePlan) else PreparedWorkspacePlan(None, deepcopy(prepared))


def _domain_evidence(model, unknown_candidates):
    return {"schemaVersion": 1, "selection": "EXPLICIT_FINITE",
            "evidenceCoverage": "PARTIAL" if unknown_candidates else "COMPLETE",
            "candidateSetDigest": sha256(json.dumps(
                [(item.name, item.current_version, item.domain) for item in model.packages],
                separators=(",", ":"), ensure_ascii=True).encode()).hexdigest(),
            "candidateCount": model.candidate_count(),
            "unprovenCandidateCount": len(unknown_candidates),
            "unprovenCandidates": unknown_candidates}


def _finish_workspace_solution(result, *, health_evidence=False):
    partial = result.get("domain", {}).get("evidenceCoverage") == "PARTIAL"
    if partial and result["status"] == "UNSAT_IN_MODELED_DOMAIN":
        result.update(status="UNKNOWN", assignment=None, reason="WORKSPACE_CANDIDATE_EVIDENCE_INCOMPLETE")
        if "policy" in result:
            result["policy"] = {**result["policy"], "status": "UNKNOWN"}
    result["optimality"] = (
        "PROVEN_IN_EVIDENCED_SUBDOMAIN" if partial or health_evidence else "PROVEN_IN_SELECTED_DOMAIN"
    ) if result["status"] == "SAT_IN_MODELED_DOMAIN" else "NOT_PROVEN"
    if result.get("assignment") is not None:
        result["assignmentDigest"] = sha256(json.dumps(
            result["assignment"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    return result


def _solve_workspace_model(model, result, timeout_ms, excluded_assignments, constraint_evidence, health_solver):
    result["modelDigest"] = sha256(json.dumps(
        {"model": asdict(model), "topology": result["topology"],
         **({"proposedNestedSlot": result["proposedNestedSlot"]} if "proposedNestedSlot" in result else {})},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    if constraint_evidence is not None:
        result["constraintEvidence"] = constraint_evidence
    if excluded_assignments:
        model = model.with_constraints(
            forbidden(model.assignment_key(vector), reason="Previously tried complete candidate",
                      provenance="workspace-request-enumeration")
            for vector in excluded_assignments
        )
    if health_solver is not None:
        return _finish_workspace_solution({**result, **health_solver(model, timeout_ms)}, health_evidence=True)
    solved = solve_z3_exact(model, timeout_ms=timeout_ms)
    if solved.status == "optimal" and solved.assignment is not None:
        return _finish_workspace_solution({**result, "status": "SAT_IN_MODELED_DOMAIN", "assignment": solved.assignment})
    if solved.status == "unsat":
        return _finish_workspace_solution({**result, "status": "UNSAT_IN_MODELED_DOMAIN"})
    return _finish_workspace_solution({**result, "status": "UNKNOWN", "reason": solved.detail or solved.status})


def plan_workspace_from_registry(
    packages: dict,
    declarations: Mapping[Declaration, str],
    approved_lines: Mapping[Declaration, tuple[int, ...]],
    exact_targets: Mapping[Declaration, str],
    client,
    *,
    environment: Mapping[str, str] | None = None,
    topology: WorkspaceTopology | None = None,
    candidate_limit: int = 32,
    prefetch_metadata: bool = False,
    bounded_selection: bool = False,
    timeout_ms: int = 30_000,
    candidate_versions: Mapping[Declaration, tuple[str, ...]] | None = None,
    health_policy: WorkspaceHealthPolicy | None = None,
    health_lag_months: int = 12,
    osv_allowed_names: frozenset[str] = frozenset(),
    registry_advisory_source: str | None = None,
    excluded_assignments: tuple[Mapping[str, str], ...] = (),
    include_constraint_evidence: bool = False,
    effective_peer_ranges: Mapping[tuple[str, str, str, str], str] | None = None,
    prepare_only: bool = False,
    propose_nested_slot: bool = False,
) -> dict | PreparedWorkspacePlan:
    """Read deduplicated packuments through the existing Core registry client."""
    from dependency_live_roadmap_generator import DraftBudgetExceeded, RegistryInfrastructureError

    if not approved_lines.keys() <= declarations.keys() or not exact_targets.keys() <= approved_lines.keys():
        raise ValueError("EXACT_OR_MUTABLE_TARGET_OUTSIDE_DECLARATIONS")
    if type(candidate_limit) is not int or not 1 <= candidate_limit <= 128:
        raise ValueError("INVALID_WORKSPACE_CANDIDATE_LIMIT")
    if bounded_selection and candidate_versions is not None:
        raise ValueError("WORKSPACE_SELECTION_CONFLICT")
    if candidate_versions is not None and (
            candidate_versions.keys() != approved_lines.keys()
            or any(not 1 <= len(versions) <= candidate_limit or len(versions) != len(set(versions))
                   for versions in candidate_versions.values())
            or any(target not in candidate_versions[key] for key, target in exact_targets.items())):
        raise ValueError("INVALID_WORKSPACE_ADMITTED_CANDIDATES")
    if health_policy is not None and (getattr(client, "deadline", None) is None or client.deadline.remaining is None):
        raise ValueError("WORKSPACE_POLICY_REGISTRY_DEADLINE_REQUIRED")
    if registry_advisory_source is not None:
        from registry_advisory_evidence import registry_advisory_source_matches, valid_registry_advisory_name

        if health_policy is None or client.allow_registry_metadata_redirects or not registry_advisory_source_matches(
            client.registry, registry_advisory_source,
        ):
            raise ValueError("WORKSPACE_REGISTRY_ADVISORY_NOT_AUTHORIZED")
        if not all(valid_registry_advisory_name(name) for _, _, name in declarations):
            raise ValueError("WORKSPACE_REGISTRY_ADVISORY_INVALID_PACKAGE")
    for key, target in exact_targets.items():
        version = Version(target)
        if version.prerelease or version.major not in approved_lines[key]:
            raise ValueError(f"EXACT_TARGET_OUTSIDE_APPROVED_LINES: {key}")

    unknown = {"authority": "PLANNING_ONLY", "verification": "NOT_VERIFIED",
               "topology": "PROPOSED_INSTANCE_LAYOUT" if topology else "OBSERVED_LOCK_LAYOUT", "status": "UNKNOWN", "assignment": None}
    if health_policy is not None:
        unknown["policy"] = {"status": "UNKNOWN", "targetLevel": health_policy.target,
                             "authority": "DECLARED_DOMAIN_PLANNING_ONLY", "finalAudit": "NOT_RUN"}
    packuments = {}
    admitted = {}
    candidate_evidence_errors = {}
    selection_truncated = False
    slots = {}
    # Validate the entire local boundary before sending any package name.
    for key in sorted(declarations):
        owner, _, name = key
        current = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
        if current is None:
            return {**unknown, "reason": f"WORKSPACE_SLOT_UNPROVEN: {key}"}
        path, current_version = current
        if packages[path].get("link"):
            if key in approved_lines:
                raise ValueError(f"WORKSPACE_LINK_TARGET_NOT_MUTABLE: {key}")
            continue
        slots[key] = current
    if prefetch_metadata:
        from workspace_registry_metadata import fetch_workspace_packuments
        try:
            packuments = fetch_workspace_packuments(client, [key[2] for key in slots])
        except (RegistryInfrastructureError, DraftBudgetExceeded):
            return {**unknown, "reason": "WORKSPACE_METADATA_PREFETCH_UNAVAILABLE"}
    for key, (path, current_version) in slots.items():
        name = key[2]
        if name not in packuments:
            try:
                packument = client.fetch_npm_metadata(name)
            except (RegistryInfrastructureError, DraftBudgetExceeded):
                return {**unknown, "reason": f"REGISTRY_METADATA_UNAVAILABLE: {name}"}
            packuments[name] = packument
        if not isinstance(packuments[name], dict) or not isinstance(packuments[name].get("versions"), dict):
            return {**unknown, "reason": f"REGISTRY_METADATA_UNAVAILABLE: {name}"}
        if key not in approved_lines:
            continue
        packument = packuments[name]
        current_semver = Version(current_version)
        candidates = []
        versions = ((exact_targets[key],) if key in exact_targets else
                    candidate_versions[key] if candidate_versions is not None else packument["versions"])
        for value in versions:
            if (value == current_version and key not in exact_targets
                    and (not bounded_selection or Version(value).major in approved_lines[key])):
                candidates.append(Version(value))
                continue
            try:
                version = Version(value)
            except ValueError:
                continue
            if version.prerelease or version < current_semver or version.major not in approved_lines[key]:
                continue
            if not isinstance(packument["versions"].get(value), dict):
                if candidate_versions is not None or key in exact_targets:
                    candidates.append(version)
                    candidate_evidence_errors[key, value] = "CANDIDATE_METADATA_MISSING"
                continue
            url = client.registry_tarball_url(packument, value)
            if url and client.registry_artifact_url_allowed(url):
                candidates.append(version)
            elif candidate_versions is not None or key in exact_targets or bounded_selection:
                candidates.append(version)
                candidate_evidence_errors[key, value] = "CANDIDATE_ARTIFACT_ORIGIN_UNPROVEN"
        if bounded_selection:
            ranked = sorted(set(candidates), reverse=True)
            selection_truncated |= len(ranked) > candidate_limit
            candidates = ranked[:candidate_limit]
            # Retain an admitted baseline as an alternative without exceeding K.
            if current_semver in ranked and current_semver not in candidates:
                candidates[-1] = current_semver
        if not candidates or len(candidates) > candidate_limit:
            return {**unknown, "reason": f"WORKSPACE_CANDIDATE_DOMAIN_UNAVAILABLE: {key}"}
        if candidate_versions is not None and len(candidates) != len(versions):
            return {**unknown, "reason": f"WORKSPACE_EXPLICIT_DOMAIN_INCOMPLETE: {key}"}
        admitted[key] = (tuple(str(value) for value in candidates) if candidate_versions is not None
                         else tuple(str(value) for value in sorted(candidates, reverse=True)))

    facts = evidence = None
    if health_policy is not None:
        from workspace_health_evidence import collect_workspace_health_facts, workspace_registry_health_versions

        query_versions = workspace_registry_health_versions(packages, declarations, admitted, exact_targets)
        try:
            facts, evidence = collect_workspace_health_facts(
                client, packuments, query_versions, lag_months=health_lag_months,
                osv_allowed_names=osv_allowed_names, registry_advisory_source=registry_advisory_source,
            )
        except (DraftBudgetExceeded, RegistryInfrastructureError):
            return {**unknown, "reason": "WORKSPACE_POLICY_EVIDENCE_UNAVAILABLE"}
        remaining_ms = int(client.deadline.remaining * 1000)
        if remaining_ms < 1:
            return {**unknown, "reason": "WORKSPACE_POLICY_EVIDENCE_TIMEOUT"}
        timeout_ms = min(timeout_ms, remaining_ms)
    result = plan_workspace_upgrade(
        packages, declarations, admitted, exact_targets, packuments,
        environment=environment, topology=topology, timeout_ms=timeout_ms,
        health_policy=health_policy, health_facts=facts, effective_peer_ranges=effective_peer_ranges,
        candidate_evidence_errors=candidate_evidence_errors, prepare_only=prepare_only,
        excluded_assignments=excluded_assignments, include_constraint_evidence=include_constraint_evidence,
        propose_nested_slot=propose_nested_slot,
    )
    if bounded_selection:
        selected = [{"declaration": list(key), "versions": list(versions)} for key, versions in sorted(admitted.items())]
        selection = {"rule": "LATEST_STABLE_PLUS_BASELINE_V1", "limit": candidate_limit,
                     "truncated": selection_truncated, "proofScope": "SELECTED_DOMAIN_ONLY"}
        def annotate(value):
            value = deepcopy(value)
            value.update(selectedCandidates=selected, candidateSelection=selection)
            if "domain" in value:
                value["domain"]["selection"] = "SERVER_BOUNDED"
            return value
        if isinstance(result, PreparedWorkspacePlan):
            result = replace(result, result=annotate(result.result))
        else:
            result = annotate(result)
    if health_policy is not None:
        if isinstance(result, PreparedWorkspacePlan):
            result = replace(result, policy_evidence=deepcopy(evidence))
        else:
            result.setdefault("policy", unknown["policy"])
            result["policy"]["evidence"] = evidence
    return result


def plan_workspace_upgrade(
    packages: dict,
    declarations: Mapping[Declaration, str],
    admitted_versions: Mapping[Declaration, tuple[str, ...]],
    exact_targets: Mapping[Declaration, str],
    packuments: Mapping[str, dict],
    *,
    environment: Mapping[str, str] | None = None,
    topology: WorkspaceTopology | None = None,
    timeout_ms: int = 30_000,
    excluded_assignments: tuple[Mapping[str, str], ...] = (),
    include_constraint_evidence: bool = False,
    health_policy: WorkspaceHealthPolicy | None = None,
    health_facts: Mapping[tuple[str, str], WorkspaceHealthFact] | None = None,
    candidate_evidence_errors: Mapping[tuple[Declaration, str], str] | None = None,
    effective_peer_ranges: Mapping[tuple[str, str, str, str], str] | None = None,
    prepare_only: bool = False,
    propose_nested_slot: bool = False,
) -> dict | PreparedWorkspacePlan:
    """Use a bounded metadata snapshot to plan under an npm lock layout."""
    if health_facts is not None and health_policy is None:
        raise ValueError("WORKSPACE_HEALTH_FACTS_REQUIRE_POLICY")
    try:
        if topology is not None and _workspace_owner_peer_rows(packages):
            raise WorkspaceModelUnknown("PROPOSED_LAYOUT_OWNER_PEERS_UNPROVEN")
        domains = workspace_domains_from_inputs(
            packages, declarations, admitted_versions, exact_targets, packuments, allow_partial=True)
        for key, domain in list(domains.items()):
            domains[key] = replace(domain, candidates=tuple(
                replace(candidate, evidence_reason=(candidate_evidence_errors or {}).get(
                    (key, candidate.version), candidate.evidence_reason)) for candidate in domain.candidates
            ))
    except WorkspaceModelUnknown as exc:
        return {"authority": "PLANNING_ONLY", "verification": "NOT_VERIFIED",
                "topology": "PROPOSED_INSTANCE_LAYOUT" if topology else "OBSERVED_LOCK_LAYOUT", "status": "UNKNOWN",
                "reason": str(exc), "assignment": None}
    health_solver = None
    if health_policy is not None:
        frozen_health_facts = dict(health_facts or {})
        active_names = {}
        for key in domains:
            owner, _, name = key
            instance = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
            if not packages[instance[0]].get("link"):
                active_names[declaration_id(key)] = name

        def health_solver(model, budget):
            if not active_names:
                return {"status": "UNKNOWN", "assignment": None, "reason": "WORKSPACE_POLICY_SCOPE_EMPTY"}
            result = solve_workspace_health(model, active_names, frozen_health_facts, health_policy, timeout_ms=budget)
            result["policy"]["internalLinkDeclarations"] = len(domains) - len(active_names)
            return result

    if topology is not None:
        return plan_workspace_in_topology(domains, topology.providers, topology.instance_groups,
                                          environment=environment, timeout_ms=timeout_ms,
                                          excluded_assignments=excluded_assignments,
                                          include_constraint_evidence=include_constraint_evidence,
                                          health_solver=health_solver, prepare_only=prepare_only)
    return plan_workspace_from_lock(packages, domains, environment=environment,
                                    timeout_ms=timeout_ms, excluded_assignments=excluded_assignments,
                                    include_constraint_evidence=include_constraint_evidence,
                                    health_solver=health_solver, effective_peer_ranges=effective_peer_ranges,
                                    prepare_only=prepare_only, propose_nested_slot=propose_nested_slot)
