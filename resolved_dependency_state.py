from __future__ import annotations

import dataclasses
from functools import lru_cache
import hashlib
import json
import os
import stat
import subprocess
import threading
from pathlib import Path
from typing import Mapping, Optional
from project_topology import ProjectTopologyError, resolve_project_topology

# BLOCK_Z_PROJECT_TOPOLOGY_V1

RESOLVED_STATE_SCHEMA = "resolved-state-v1"


class ResolvedDependencyStateError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class ResolvedDependencyState:
    key: str
    resolver_input_key: str
    manager: str
    lockfile_path: str
    lockfile_hash: str
    observed_resolved_hash: str
    artifact_relative_path: str
    lockfile_bytes: bytes = dataclasses.field(repr=False, compare=False)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _git_root_or_project(project_dir: Path) -> Path:
    from git_identity import git_toplevel

    root = git_toplevel(project_dir)
    if root is not None:
        return root
    return Path(project_dir).resolve()


def _lockfile_names(manager: str) -> tuple[str, ...]:
    manager = str(manager).lower()
    if manager == "yarn":
        return ("yarn.lock",)
    if manager == "pnpm":
        return ("pnpm-lock.yaml",)
    if manager == "npm":
        return ("npm-shrinkwrap.json", "package-lock.json")
    raise ResolvedDependencyStateError(f"RESOLVED_STATE_MANAGER_UNSUPPORTED: {manager}")


def _find_lockfile(project_dir: Path, manager: str) -> tuple[Path, Path]:
    project_dir = project_dir.resolve()
    try:
        topology = resolve_project_topology(
            project_dir,
            allow_discovery=False,
            require_supported=True,
        )
    except ProjectTopologyError as exc:
        raise ResolvedDependencyStateError(
            f"RESOLVED_STATE_PROJECT_TOPOLOGY_UNAVAILABLE: {exc}"
        ) from exc
    if topology.profile.manager != str(manager).lower():
        raise ResolvedDependencyStateError(
            "RESOLVED_STATE_MANAGER_TOPOLOGY_MISMATCH: "
            f"requested={manager}; topology={topology.profile.manager}"
        )
    identity_root = topology.git_root or topology.source_root
    return identity_root.resolve(), topology.lockfile.resolve()


def _state_key(
    *,
    resolver_input_key: str,
    manager: str,
    lockfile_path: str,
    lockfile_hash: str,
    observed_resolved_hash: str,
) -> str:
    return _canonical_hash({
        "schema": RESOLVED_STATE_SCHEMA,
        "resolverInputKey": str(resolver_input_key),
        "manager": str(manager),
        "lockfilePath": str(lockfile_path),
        "lockfileHash": str(lockfile_hash),
        "observedResolvedHash": str(observed_resolved_hash),
    })


def capture_resolved_dependency_state(
    project_dir: Path,
    *,
    manager: str,
    resolver_input_key: str,
    observed_resolved_hash: str,
    proof_cache_dir: Optional[Path],
) -> ResolvedDependencyState:
    git_root, lockfile = _find_lockfile(project_dir, manager)
    try:
        lockfile_bytes = lockfile.read_bytes()
    except OSError as exc:
        raise ResolvedDependencyStateError(
            f"RESOLVED_STATE_LOCKFILE_UNREADABLE: {lockfile}: {exc}"
        ) from exc
    lockfile_hash = _sha256_bytes(lockfile_bytes)
    try:
        lockfile_path = lockfile.relative_to(git_root).as_posix()
    except ValueError as exc:
        raise ResolvedDependencyStateError(
            f"RESOLVED_STATE_LOCKFILE_OUTSIDE_GIT_ROOT: {lockfile}"
        ) from exc

    key = _state_key(
        resolver_input_key=resolver_input_key,
        manager=manager,
        lockfile_path=lockfile_path,
        lockfile_hash=lockfile_hash,
        observed_resolved_hash=observed_resolved_hash,
    )
    artifact_relative_path = ""
    if proof_cache_dir is not None:
        root = proof_cache_dir.resolve()
        artifact = root / "resolved-state" / key / "lockfile.bin"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        if artifact.exists():
            existing = artifact.read_bytes()
            if _sha256_bytes(existing) != lockfile_hash:
                raise ResolvedDependencyStateError(
                    f"RESOLVED_STATE_ARTIFACT_COLLISION: {artifact}"
                )
        else:
            temporary = artifact.with_name(
                f"{artifact.name}.tmp-{os.getpid()}-{threading_get_ident()}"
            )
            temporary.write_bytes(lockfile_bytes)
            os.replace(temporary, artifact)
        artifact_relative_path = artifact.relative_to(root).as_posix()

    return ResolvedDependencyState(
        key=key,
        resolver_input_key=str(resolver_input_key),
        manager=str(manager),
        lockfile_path=lockfile_path,
        lockfile_hash=lockfile_hash,
        observed_resolved_hash=str(observed_resolved_hash),
        artifact_relative_path=artifact_relative_path,
        lockfile_bytes=lockfile_bytes,
    )


def threading_get_ident() -> int:
    # Kept local to avoid importing threading on the hot path unless persistence is used.
    import threading
    return threading.get_ident()


# Restore of a SHARED lockfile needs mutual exclusion, not just identity.
# The resolved-state key binds *content identity*: it proves exactly which
# bytes belong to a state, but it cannot by itself stop two verification
# attempts from concurrently restoring the same lockfile pathname (for example
# one root lockfile shared by several monorepo packages). os.replace already
# prevents a torn byte stream. The hash assertion detects observed drift, but
# does not grant cross-process exclusion or lock the following install. Actual
# verifier installs run in isolated clones, each with its own root lockfile.
# The per-path lock below makes
# write+verify one atomic critical section per pathname within this process, so
# concurrent restores of the same shared lockfile are serialized instead of
# interleaving their critical sections.
_RESTORE_TARGET_LOCKS: dict[str, threading.Lock] = {}
_RESTORE_TARGET_LOCKS_GUARD = threading.Lock()


def _restore_target_lock(target: Path) -> threading.Lock:
    key = os.path.normcase(str(Path(target).resolve()))
    with _RESTORE_TARGET_LOCKS_GUARD:
        lock = _RESTORE_TARGET_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _RESTORE_TARGET_LOCKS[key] = lock
        return lock


def resolved_state_metadata(state: ResolvedDependencyState) -> dict[str, str]:
    return {
        "resolvedStateKey": state.key,
        "resolvedStateResolverInputKey": state.resolver_input_key,
        "resolvedPackageManager": state.manager,
        "resolvedLockfilePath": state.lockfile_path,
        "resolvedLockfileHash": state.lockfile_hash,
        "resolvedStateArtifact": state.artifact_relative_path,
        "resolvedStateObservedHash": state.observed_resolved_hash,
    }


def load_resolved_dependency_state(
    metadata: Mapping[str, object],
    *,
    proof_cache_dir: Optional[Path],
) -> Optional[ResolvedDependencyState]:
    try:
        key = str(metadata.get("resolvedStateKey") or "")
        resolver_input_key = str(metadata.get("resolvedStateResolverInputKey") or "")
        manager = str(metadata.get("resolvedPackageManager") or "")
        lockfile_path = str(metadata.get("resolvedLockfilePath") or "")
        lockfile_hash = str(metadata.get("resolvedLockfileHash") or "")
        artifact_relative_path = str(metadata.get("resolvedStateArtifact") or "")
        observed_hash = str(metadata.get("resolvedStateObservedHash") or "")
        if not (
            len(key) == 64
            and len(lockfile_hash) == 64
            and len(observed_hash) == 64
            and resolver_input_key
            and manager
            and lockfile_path
            and artifact_relative_path
            and proof_cache_dir is not None
        ):
            return None

        root = proof_cache_dir.resolve()
        artifact = (root / Path(artifact_relative_path)).resolve()
        try:
            artifact.relative_to(root)
        except ValueError:
            return None
        if not artifact.is_file():
            return None
        lockfile_bytes = artifact.read_bytes()
        if _sha256_bytes(lockfile_bytes) != lockfile_hash:
            return None
        expected = _state_key(
            resolver_input_key=resolver_input_key,
            manager=manager,
            lockfile_path=lockfile_path,
            lockfile_hash=lockfile_hash,
            observed_resolved_hash=observed_hash,
        )
        if expected != key:
            return None
        return ResolvedDependencyState(
            key=key,
            resolver_input_key=resolver_input_key,
            manager=manager,
            lockfile_path=lockfile_path,
            lockfile_hash=lockfile_hash,
            observed_resolved_hash=observed_hash,
            artifact_relative_path=artifact_relative_path,
            lockfile_bytes=lockfile_bytes,
        )
    except (OSError, TypeError, ValueError):
        return None


def resolved_lockfile_path(project_dir: Path, state: ResolvedDependencyState) -> Path:
    git_root = _git_root_or_project(project_dir)
    target = (git_root / Path(state.lockfile_path)).resolve()
    try:
        target.relative_to(git_root)
    except ValueError as exc:
        raise ResolvedDependencyStateError(
            f"RESOLVED_STATE_LOCKFILE_PATH_ESCAPE: {state.lockfile_path}"
        ) from exc
    return target


def restore_resolved_dependency_state(
    project_dir: Path, state: ResolvedDependencyState
) -> Path:
    target = resolved_lockfile_path(project_dir, state)
    with _restore_target_lock(target):
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f"{target.name}.deploom-resolved-{os.getpid()}.tmp")
        temporary.write_bytes(state.lockfile_bytes)
        os.replace(temporary, target)
        assert_resolved_dependency_state(project_dir, state)
    return target


def assert_resolved_dependency_state(
    project_dir: Path, state: ResolvedDependencyState
) -> None:
    target = resolved_lockfile_path(project_dir, state)
    if not target.is_file():
        raise ResolvedDependencyStateError(
            f"RESOLVED_STATE_LOCKFILE_DISAPPEARED: {state.lockfile_path}"
        )
    current_hash = _sha256_bytes(target.read_bytes())
    if current_hash != state.lockfile_hash:
        raise ResolvedDependencyStateError(
            "RESOLVED_STATE_LOCKFILE_DRIFT: "
            f"expected={state.lockfile_hash} current={current_hash} path={state.lockfile_path}"
        )


class MaterializedDependencyObligationError(RuntimeError):
    """Unknown installed evidence is never solver incompatibility or a nogood."""


def _obligation_json(raw, limit=8*1024*1024):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    try:
        if not isinstance(raw, bytes) or len(raw) > limit:
            raise ValueError('size/type')
        result = json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        if not isinstance(result, dict):
            raise ValueError('object required')
        return result
    except (UnicodeError, ValueError) as exc:
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_JSON_UNPROVEN') from exc


def _ordinary_npm_obligation_mode(record, *, bundle_verified=False):
    for key in ('link', 'inBundle'):
        if key in record and (type(record[key]) is not bool or record[key] and not (key=='inBundle' and bundle_verified)):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_BUNDLE_OR_LINK_UNSUPPORTED')
    for key in ('bundleDependencies', 'bundledDependencies'):
        if key in record and not (record[key] is False or type(record[key]) is list and (not record[key] or bundle_verified)):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_BUNDLED_UNSUPPORTED')


def _npm_obligation_name(location, record):
    import re
    # Historical npm records can contain ASCII capitals. Preserve exact case;
    # graph/physical casefold collision checks remain independently mandatory.
    segment = r'(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*'
    if (not isinstance(location, str)
            or re.fullmatch(r'node_modules/'+segment+r'(?:/node_modules/'+segment+r')*', location) is None):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_PATH_UNPROVEN')
    installed_name = location.rsplit('/node_modules/', 1)[-1].removeprefix('node_modules/')
    canonical_name = record.get('name', installed_name)
    if (not isinstance(canonical_name, str) or re.fullmatch(segment, canonical_name) is None
            or record.get('link') or not isinstance(record.get('version'), str)):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_IDENTITY_UNPROVEN')
    from semantic_version import Version
    try:
        Version(record['version'])
    except ValueError as exc:
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_VERSION_UNPROVEN') from exc
    return installed_name, canonical_name


def compile_npm_dependency_obligations(baseline_lock_bytes, candidate_lock_bytes, *,
        exact_targets, changed_instances, immutable_packages=(), excluded_packages=(),
        delta_digest, scope_digest, optional_absence_rules=(), bundled_owner_rules=None):
    """Compile expected npm-v2/v3 obligations BEFORE observing installed output.

    Exact host delta/scope authorization remains with its existing owner. This
    compiler independently binds that delta to both lock graphs. It does not
    infer authorization, tarball authenticity or arbitrary runtime behavior.
    """
    import re
    before, after = (_obligation_json(raw) for raw in (baseline_lock_bytes, candidate_lock_bytes))
    if (any(type(lock.get('lockfileVersion')) is not int or lock['lockfileVersion'] not in (2,3)
            or lock['lockfileVersion']==3 and 'dependencies' in lock for lock in (before, after))
            or before['lockfileVersion']!=after['lockfileVersion']):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_LOCK_UNSUPPORTED')
    omission_proof={}
    if optional_absence_rules:
        from npm_platform_obligations import verify_platform_absence,NpmPlatformEvidenceError
        try:omission_proof=verify_platform_absence(after,optional_absence_rules)
        except (NpmPlatformEvidenceError,OSError) as exc:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_PLATFORM_UNPROVEN: '+str(exc)) from exc
    if any(not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None
            for value in (delta_digest, scope_digest)):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_AUTHORIZATION_UNPROVEN')
    bundle_proofs={};bundle_paths=set()
    if bundled_owner_rules is not None:
        from npm_bundle_obligations import compile_bundle_rules,NpmBundleEvidenceError
        try:bundle_proofs=compile_bundle_rules(before,after,bundled_owner_rules,baseline_lock_bytes)
        except (NpmBundleEvidenceError,OSError) as exc:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_BUNDLE_UNPROVEN: '+str(exc)) from exc
        for owner,proof in bundle_proofs.items():bundle_paths.update([owner,*proof['memberRecordDigests']])
    graphs = []
    for lock in (before, after):
        graph = lock.get('packages')
        if (not isinstance(graph, dict) or '' not in graph or not isinstance(graph[''], dict)
                or len(graph) > 10001 or any(not isinstance(row, dict) for row in graph.values())
                or len({name.casefold() for name in graph}) != len(graph)):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_GRAPH_UNPROVEN')
        for location, row in graph.items():
            _ordinary_npm_obligation_mode(row,bundle_verified=location in bundle_paths)
            if location:
                _npm_obligation_name(location, row)
        graphs.append(graph)
    old, new = graphs
    v2_aliases={}
    if before['lockfileVersion']==2 and any(
            _npm_obligation_name(path,row)[0]!=_npm_obligation_name(path,row)[1]
            for graph in graphs for path,row in graph.items() if path):
        from npm_platform_obligations import v2_alias_bindings,NpmPlatformEvidenceError
        try:
            old_aliases,new_aliases=v2_alias_bindings(before),v2_alias_bindings(after)
            if old_aliases!=new_aliases:raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_V2_ALIAS_CHANGED')
            v2_aliases=new_aliases
        except NpmPlatformEvidenceError as exc:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_V2_ALIAS_UNPROVEN') from exc
    # Lexical historical compatibility is not permission for a new or changed
    # mixed-case instance. Only exact original records retain that identity.
    for location, row in new.items():
        if not location:continue
        alias, name = _npm_obligation_name(location, row)
        if any(c.isupper() for c in alias + name) and old.get(location) != row:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_HISTORICAL_INSTANCE_CHANGED')
    changed = {name for name in set(old) | set(new) if name and old.get(name) != new.get(name)}
    if (not isinstance(changed_instances, (list, tuple))
            or any(not isinstance(name, str) for name in changed_instances)
            or len(set(changed_instances)) != len(changed_instances) or set(changed_instances) != changed):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_DELTA_MISMATCH')
    protected = set(immutable_packages) | set(excluded_packages)
    for location in changed:
        for graph in (old, new):
            if location in graph and protected.intersection(_npm_obligation_name(location, graph[location])):
                raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_PROTECTED_DELTA')
    sections = ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies')
    root_before = {key: old[''].get(key, {}) for key in sections}
    root_after = {key: new[''].get(key, {}) for key in sections}
    expected = json.loads(json.dumps(root_before))
    for name, version in exact_targets.items():
        found = [key for key in sections if isinstance(expected[key], dict) and name in expected[key]]
        if len(found) != 1:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_ROOT_UNPROVEN')
        expected[found[0]][name] = version
    if expected != root_after:
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_ROOT_SCOPE_MISMATCH')
    instances = []
    for location in sorted(set(new) - {''}):
        row = new[location]; alias, name = _npm_obligation_name(location, row)
        instances.append({'path': location, 'installName': alias, 'name': name, 'version': row['version'],
            'lockRecordDigest': _canonical_hash(row), 'held': location in old and location not in changed,
            'metadata': {key: row.get(key, {}) for key in
                ('dependencies', 'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta')}})
    plan = {'schemaVersion': 1, 'kind': 'APPROVED_NPM_V'+str(after['lockfileVersion'])+'_INSTANCE_OBLIGATIONS',
        'baselineLockSha256': _sha256_bytes(baseline_lock_bytes),
        'approvedLockSha256': _sha256_bytes(candidate_lock_bytes),
        'approvedDeltaDigest': delta_digest, 'allowedChangeScopeDigest': scope_digest,
        'rootDeclarations': root_after, 'instances': instances, 'changedInstanceCount': len(changed),
        'optionalAbsenceRules': optional_absence_rules if omission_proof else []}
    if omission_proof:plan['platformAbsenceProof']=omission_proof
    if bundle_proofs:plan.update(bundledOwnerRules=bundled_owner_rules,unchangedBundledOwners=bundle_proofs)
    if v2_aliases:plan['unchangedNpmV2Aliases']=v2_aliases
    return {**plan, 'obligationPlanDigest': _canonical_hash(plan)}


def npm_root_assignment_from_obligations(plan):
    """Declared roots only; hoisted transitive instances stay in physical scope."""
    if (not isinstance(plan,dict) or plan.get('obligationPlanDigest')!=_canonical_hash(
            {k:v for k,v in plan.items() if k!='obligationPlanDigest'})):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_PLAN_UNPROVEN')
    declarations=plan.get('rootDeclarations');instances=plan.get('instances')
    if not isinstance(declarations,dict) or not isinstance(instances,list):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_ROOT_UNPROVEN')
    names=set()
    for section in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
        rows=declarations.get(section,{})
        if not isinstance(rows,dict):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_ROOT_UNPROVEN')
        for name in rows:
            if not isinstance(name,str) or _npm_obligation_name('node_modules/'+name,{'version':'0.0.0'})[0]!=name:
                raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_ROOT_UNPROVEN')
            names.add(name)
    by_path={row['path']:row for row in instances}
    result={}
    for name in sorted(names):
        row=by_path.get('node_modules/'+name)
        if not row or row.get('installName')!=name:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_DECLARED_ROOT_INSTANCE_UNPROVEN')
        result[name]=row['version']
    return result


def observe_npm_dependency_obligations(project_dir, plan, *, source_origin_digest, resolved_state_key, deadline=None, auxiliary_directory_observer=None):
    """Observe actual physical instance manifests and supported Node edge paths.

    Boundary observation, not continuous mutation or package-payload attestation.
    Only empty unlocked unscoped dot directories are auxiliary non-packages;
    scoped slots, nonempty entries and reparse paths remain unproven. Optional
    auxiliary diagnostics are separate from the package graph and denominator.
    Missing optional instances remain UNKNOWN until explicit omission semantics
    are supported; they never disappear from the expected denominator.
    """
    import re
    from semantic_version import NpmSpec, Version
    from project_runtime import normalize_npm_range
    import time

    @lru_cache(maxsize=1024)
    def parse_range(spec):
        return NpmSpec(normalize_npm_range(spec))

    def budget():
        if deadline is not None and time.monotonic() >= deadline:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_DEADLINE_EXCEEDED')
    budget()
    project = Path(project_dir).resolve()
    if (not isinstance(plan, dict) or type(plan.get('schemaVersion')) is not int or plan['schemaVersion'] != 1
            or plan.get('obligationPlanDigest') != _canonical_hash({k: v for k, v in plan.items() if k != 'obligationPlanDigest'})):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_PLAN_UNPROVEN')
    if any(not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None
            for value in (source_origin_digest, resolved_state_key)):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_ORIGIN_UNPROVEN')
    from reparse_materialization import is_reparse
    from workspace_npm_obligations import WORKSPACE_OBLIGATION_KIND, _owners
    workspace = plan.get("kind") == WORKSPACE_OBLIGATION_KIND
    if workspace and Path(project_dir).absolute() != project:
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_REPARSE_UNPROVEN')

    def no_link(path):
        try:
            observed = path.lstat()
        except FileNotFoundError:
            return
        if (stat.S_ISLNK(observed.st_mode)
                or getattr(observed, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_REPARSE_UNPROVEN')
        return observed

    lock = project / 'package-lock.json'
    lock_info = no_link(lock)
    lock_bytes = lock.read_bytes() if lock_info and stat.S_ISREG(lock_info.st_mode) else b""
    if _sha256_bytes(lock_bytes) != plan['approvedLockSha256']:
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_LOCK_DRIFT')
    locked=_obligation_json(lock_bytes, 32 * 1024 * 1024 if workspace else 8 * 1024 * 1024)
    if (type(locked.get('lockfileVersion')) is not int or locked['lockfileVersion'] not in (2,3)
            or locked['lockfileVersion']==3 and 'dependencies' in locked
            or (workspace and locked['lockfileVersion'] != 3)
            or (not workspace and plan.get('kind')!='APPROVED_NPM_V'+str(locked['lockfileVersion'])+'_INSTANCE_OBLIGATIONS')):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_LOCK_UNSUPPORTED')
    owners = plan["workspaceOwners"] if workspace else {"": {"declarations": plan["rootDeclarations"]}}
    workspace_links = plan["workspaceLinks"] if workspace else {}
    if workspace:
        _owners(locked["packages"], {owner or ".": row["manifestSha256"] for owner, row in owners.items()})
        if (not isinstance(workspace_links, dict)
                or set(workspace_links) != {slot for slot, row in locked["packages"].items() if row.get("link")}
                or {row["owner"] for row in workspace_links.values()} != set(owners) - {""}
                or len(workspace_links) != len(owners) - 1):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_WORKSPACE_LINKS_UNPROVEN')

    def read_owner(owner, expected_owner):
        budget()
        directory = project
        for part in owner.split("/") if owner else ():
            directory /= part
            no_link(directory)
        path = directory / "package.json"
        no_link(path)
        limit = (2 if workspace else 1) * 1024 * 1024
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        manifest = _obligation_json(raw, limit)
        _ordinary_npm_obligation_mode(manifest)
        if ({key: manifest.get(key, {}) for key in expected_owner["declarations"]} != expected_owner["declarations"]
                or (workspace and _sha256_bytes(raw) != expected_owner["manifestSha256"])):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_MANIFEST_DRIFT')
        return manifest

    owner_manifests = {owner: read_owner(owner, row) for owner, row in owners.items()}
    for slot, row in workspace_links.items():
        owner = row["owner"]
        if (slot != "node_modules/" + row["name"] or locked["packages"][slot] != {"link": True, "resolved": owner}
                or owner_manifests[owner].get("name") != row["name"]
                or owner_manifests[owner].get("version") != row["version"]):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_WORKSPACE_LINKS_UNPROVEN')
        _npm_obligation_name(slot, {"version": row["version"]})
    expected = {row['path']: row for row in plan['instances']}
    omission_proof={}
    if plan.get('optionalAbsenceRules'):
        from npm_platform_obligations import verify_platform_absence,NpmPlatformEvidenceError
        try:omission_proof=verify_platform_absence(locked,plan['optionalAbsenceRules'])
        except (NpmPlatformEvidenceError,OSError) as exc:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_PLATFORM_UNPROVEN: '+str(exc)) from exc
        if omission_proof!=plan.get('platformAbsenceProof'):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_PLATFORM_PROOF_DRIFT')
    elif plan.get('platformAbsenceProof'):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_PLATFORM_PROOF_UNBOUND')
    bundle_proofs={};bundle_paths=set()
    if plan.get('bundledOwnerRules') is not None:
        from npm_bundle_obligations import compile_bundle_rules,NpmBundleEvidenceError,compare_installed_owner
        rules=plan['bundledOwnerRules']
        try:
            baseline=(Path(rules['baselineProjectPath'])/'package-lock.json').read_bytes()
            if _sha256_bytes(baseline)!=plan['baselineLockSha256']:raise NpmBundleEvidenceError('BASELINE_LOCK_DRIFT')
            bundle_proofs=compile_bundle_rules(_obligation_json(baseline),locked,rules,baseline)
            if bundle_proofs!=plan.get('unchangedBundledOwners'):raise NpmBundleEvidenceError('PROOF_DRIFT')
            for owner,proof in bundle_proofs.items():
                compare_installed_owner(project,proof)
                bundle_paths.update([owner,*proof['memberRecordDigests']])
        except (NpmBundleEvidenceError,OSError,KeyError,TypeError) as exc:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_BUNDLE_UNPROVEN: '+str(exc)) from exc
    elif plan.get('unchangedBundledOwners'):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_BUNDLE_PROOF_UNBOUND')
    actual = {}; folded = set(); manifest_bytes_read = 0
    auxiliary=[]
    locked_paths_folded={path.casefold() for path in expected}
    if auxiliary_directory_observer is not None and not callable(auxiliary_directory_observer):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_AUXILIARY_OBSERVER_INVALID')
    observed_links = {}
    manifest_size_limit = 1024 * 1024

    def scan_modules(directory, depth=0):
        nonlocal manifest_bytes_read
        budget()
        if depth > 64:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_DEPTH_LIMIT')
        if no_link(directory) is None:
            return
        for entry in sorted(directory.iterdir(), key=lambda p: p.name):
            if entry.name in {'.bin', '.package-lock.json'}:
                continue
            relative = entry.relative_to(project).as_posix()
            entry_info = None if relative in workspace_links else no_link(entry)
            # Only unscoped direct slots here: NEVER apply this predicate to
            # children inside @scope, where dot names may denote packages.
            is_directory = entry_info is not None and stat.S_ISDIR(entry_info.st_mode)
            if entry.name.startswith('.') and entry.name not in {'.','..'} and is_directory:
                if relative.casefold() not in locked_paths_folded:
                    first = entry_info
                    if getattr(first,'st_file_attributes',0)&0x400:
                        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_REPARSE_UNPROVEN')
                    if not any(entry.iterdir()):
                        no_link(entry);last=entry.lstat()
                        identity=lambda st:(st.st_dev,st.st_ino,st.st_mode,st.st_mtime_ns,st.st_ctime_ns)
                        if (identity(first)!=identity(last) or getattr(last,'st_file_attributes',0)&0x400
                                or entry.resolve().parent!=directory.resolve() or not entry.resolve().is_relative_to(project)):
                            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_AUXILIARY_LAYOUT_UNPROVEN')
                        auxiliary.append({'relativePath':relative,'classification':'UNSCOPED_NONPACKAGE_EMPTY_DIRECTORY',
                            'emptyObserved':True,'linkFreeObserved':True})
                        continue
            if entry.name.startswith('@'):
                if not is_directory:
                    raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_LAYOUT_UNPROVEN')
                paths = sorted(entry.iterdir(), key=lambda p: p.name)
            else:
                paths = [entry]
            for package in paths:
                budget()
                relative = package.relative_to(project).as_posix()
                if relative in workspace_links:
                    link = workspace_links[relative]
                    target = project / link["owner"]
                    try:
                        matches = is_reparse(package) and package.resolve(strict=True) == target and target.is_dir()
                    except (OSError, RuntimeError):
                        matches = False
                    if not matches:
                        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_WORKSPACE_LINK_MISMATCH')
                    observed_links[relative] = link["owner"]
                    continue
                package_info = entry_info if package == entry else no_link(package)
                if (relative.casefold() in folded or package_info is None
                        or not stat.S_ISDIR(package_info.st_mode) or len(actual) >= 10000):
                    raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_LAYOUT_UNPROVEN')
                folded.add(relative.casefold())
                package_file = package / 'package.json'
                file_info = no_link(package_file)
                if file_info is None or not stat.S_ISREG(file_info.st_mode):
                    raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_PACKAGE_MISSING')
                if file_info.st_size > manifest_size_limit:
                    raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_MANIFEST_SIZE_LIMIT')
                with package_file.open("rb") as stream:
                    raw = stream.read(file_info.st_size + 1)
                if len(raw) != file_info.st_size:
                    raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_MANIFEST_DRIFT')
                manifest_bytes_read += len(raw)
                if manifest_bytes_read > 64*1024*1024:
                    raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_MANIFEST_BUDGET_LIMIT')
                value = _obligation_json(raw, manifest_size_limit)
                _ordinary_npm_obligation_mode(value,bundle_verified=relative in bundle_paths)
                actual[relative] = (value, _sha256_bytes(raw))
                scan_modules(package / 'node_modules', depth+1)
    for owner in owners:
        scan_modules(project / owner / 'node_modules')
    if set(observed_links) != set(workspace_links):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_WORKSPACE_LINK_MISMATCH')
    if set(actual) != set(expected)-set(omission_proof):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_INSTANCE_SET_MISMATCH: '
            + json.dumps({'missing': sorted(set(expected)-set(actual))[:20], 'extra': sorted(set(actual)-set(expected))[:20]}))
    rows = []; edges = []
    def parent_instance(location):
        return location.rpartition('/node_modules/')[0] if '/node_modules/' in location else ''
    def resolve(location, name, peer=False):
        _npm_obligation_name('node_modules/'+name, {'version': '0.0.0'})
        if workspace:
            from resolution_inventory import _member_ancestor_prefixes
            from workspace_npm_lock_delta import peer_context
            context = peer_context(location) if peer else location
            for base in _member_ancestor_prefixes(context):
                candidate = (base + "/" if base else "") + "node_modules/" + name
                if candidate in actual or candidate in observed_links:
                    return candidate
            return None
        base = parent_instance(location) if peer else location
        while True:
            candidate = (base+'/' if base else '')+'node_modules/'+name
            if candidate in actual:
                return candidate
            if not base:
                return None
            base = parent_instance(base)
    def edge(source, name, spec, peer=False, optional=False, optional_peer=False):
        if not isinstance(spec, str):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_EDGE_UNPROVEN')
        destination = resolve(source, name, peer)
        if destination is None:
            if optional and omission_proof:
                matches=[path for path,proof in omission_proof.items() if any(
                    r['owner']==source and r['name']==name and r['specifier']==spec for r in proof['incoming'])]
                if len(matches)==1:
                    edges.append({'source':source,'name':name,'destination':matches[0],'peer':peer,'specifier':spec,
                        'outcome':'VERIFIED_PLATFORM_INAPPLICABLE'});return
            if optional_peer and (workspace or plan.get('optionalAbsenceRules')):
                try:parse_range(spec)
                except (ValueError,TypeError) as exc:
                    raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_OPTIONAL_PEER_RANGE_UNPROVEN') from exc
                edges.append({'source':source,'name':name,'destination':None,'peer':True,'specifier':spec,
                    'outcome':'DECLARED_OPTIONAL_PEER_ABSENT'});return
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_EDGE_MISSING')
        wanted_name = None
        if spec.startswith('npm:'):
            match = re.fullmatch(r'npm:((?:@[^/]+/)?[^@]+)@(.+)', spec)
            if not match:
                raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_ALIAS_UNPROVEN')
            wanted_name, spec = match.groups()
        provider = owner_manifests[observed_links[destination]] if destination in observed_links else actual[destination][0]
        try:
            matched = parse_range(spec).match(Version(provider['version']))
        except (ValueError, KeyError) as exc:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_EDGE_UNPROVEN') from exc
        expected_name = wanted_name if wanted_name is not None else name
        if provider.get('name') != expected_name:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_EDGE_IDENTITY_MISMATCH')
        if not matched:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_EDGE_MISMATCH')
        edges.append({'source': source, 'name': name, 'destination': destination, 'peer': peer, 'specifier': spec})
    for location, wanted in expected.items():
        if location in omission_proof:continue
        value, digest = actual[location]
        if value.get('name') != wanted['name'] or value.get('version') != wanted['version']:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_IDENTITY_MISMATCH: '+location)
        for key, metadata in wanted['metadata'].items():
            if not isinstance(metadata, dict) or value.get(key, {}) != metadata:
                raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_METADATA_UNPROVEN: '+location)
        for key in ('dependencies', 'optionalDependencies', 'peerDependencies'):
            for name, spec in wanted['metadata'][key].items():
                if key == 'dependencies' and name in wanted['metadata']['optionalDependencies']:
                    continue  # npm optionalDependencies override ordinary declarations.
                # Optional absence is intentionally not inferred from a missing
                # file or a successful npm exit. It remains a visible UNKNOWN.
                peer_optional=(key=='peerDependencies' and isinstance(wanted['metadata']['peerDependenciesMeta'].get(name),dict)
                    and wanted['metadata']['peerDependenciesMeta'][name].get('optional') is True)
                edge(location,name,spec,key=='peerDependencies',optional=key=='optionalDependencies',optional_peer=peer_optional)
        rows.append({'path': location, 'name': wanted['name'], 'version': wanted['version'],
            'packageManifestSha256': digest, 'lockRecordDigest': wanted['lockRecordDigest'], 'held': wanted['held']})
    for owner, record in owners.items():
        for key, declarations in record["declarations"].items():
            if not isinstance(declarations, dict):
                raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_ROOT_UNPROVEN')
            for name, spec in declarations.items():
                if key == 'dependencies' and name in record["declarations"]['optionalDependencies']:
                    continue
                optional_peer = False
                if workspace and key == "peerDependencies":
                    flags = owner_manifests[owner].get("peerDependenciesMeta", {}).get(name, {})
                    optional_peer = flags.get("optional") is True
                edge(owner, name, spec, peer=workspace and key == "peerDependencies",
                     optional=key == "optionalDependencies", optional_peer=optional_peer)
    workspace_evidence = {}
    if workspace:
        for owner, record in owners.items():
            read_owner(owner, record)
        no_link(lock)
        if lock.read_bytes() != lock_bytes:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_LOCK_DRIFT')
        for slot, owner in observed_links.items():
            path = project / slot
            if not is_reparse(path) or path.resolve() != project / owner:
                raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_WORKSPACE_LINK_MISMATCH')
        workspace_evidence = {"workspaceOwnerCount": len(owners), "workspaceLinkCount": len(observed_links),
                              "workspaceBindingDigest": _canonical_hash({
                                  "owners": owners, "links": observed_links, "resolver": plan["resolverIdentitySha256"],
                              })}
    budget()
    if auxiliary_directory_observer is not None:auxiliary_directory_observer(auxiliary)
    bundle_counts=({'bundledMemberCount':sum(p['memberCount'] for p in bundle_proofs.values()),
        'unchangedBundledOwnerCount':len(bundle_proofs),'bundledPreservationDigest':_canonical_hash(bundle_proofs)} if bundle_proofs else {})
    platform_counts=({'observedInstanceCount':len(rows),'platformInapplicableInstanceCount':len(omission_proof),
        'platformInapplicableInstances':[omission_proof[k] for k in sorted(omission_proof)]} if omission_proof else {})
    return {'schemaVersion': 1, 'authority': 'NON_REUSABLE_CORE_OBSERVATION',
        'status': 'MATERIALIZED_NPM_INSTANCE_OBLIGATIONS_OBSERVED',
        'sourceOriginObservationDigest': source_origin_digest, 'resolvedStateKey': resolved_state_key,
        'approvedLockSha256': plan['approvedLockSha256'], 'obligationPlanDigest': plan['obligationPlanDigest'],
        'materializedTreeObservationDigest': _canonical_hash({'instances': rows, 'edges': edges,
            **({'platformInapplicable':omission_proof} if omission_proof else {}), **bundle_counts, **workspace_evidence}),
        'instanceCount': len(rows)+len(omission_proof),
        'heldInstanceCount': sum(row['held'] for row in rows)+sum(expected[path]['held'] for path in omission_proof),
        **platform_counts, **bundle_counts, **workspace_evidence,
        'protectedEdgeCount': len(edges), 'changedInstanceCount': plan['changedInstanceCount'],
        'unknownCount': 0, 'violations': [], 'payloadAuthenticity': 'NOT_ATTESTED',
        'scope': 'PHYSICAL_INSTANCE_MANIFESTS_AND_SUPPORTED_NODE_EDGES_AT_BOUNDARIES', 'fullAcceptance': False}
