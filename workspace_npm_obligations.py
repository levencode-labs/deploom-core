"""Compile physical npm workspace obligations from a successful local resolver receipt."""
from __future__ import annotations

import hashlib
import json
import re

from reparse_materialization import is_reparse

from resolved_dependency_state import (
    MaterializedDependencyObligationError,
    _canonical_hash,
    _npm_obligation_name,
    _obligation_json,
    _ordinary_npm_obligation_mode,
    _sha256_bytes,
)

WORKSPACE_OBLIGATION_KIND = "APPROVED_NPM_V3_WORKSPACE_INSTANCE_OBLIGATIONS"
SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
INSTANCE_METADATA = ("dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta")
OWNER_PATH = re.compile(r"[A-Za-z0-9_-]+(?:[.][A-Za-z0-9_-]+)*(?:/[A-Za-z0-9_-]+(?:[.][A-Za-z0-9_-]+)*)*")


def _fail(code):
    raise MaterializedDependencyObligationError("WORKSPACE_OBLIGATION_" + code)


def _owners(packages, hashes):
    if not isinstance(hashes, dict) or "." not in hashes or not 2 <= len(hashes) <= 256:
        _fail("OWNERS_UNPROVEN")
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in hashes.items()):
        _fail("OWNERS_UNPROVEN")
    owners = {"" if key == "." else key: value for key, value in hashes.items()}
    if len({key.casefold() for key in owners}) != len(owners):
        _fail("OWNERS_UNPROVEN")
    for owner, digest in owners.items():
        if (owner and (not OWNER_PATH.fullmatch(owner)
                       or "node_modules" in owner.casefold().split("/"))) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            _fail("OWNERS_UNPROVEN")
    if set(owners) != {key for key in packages if "node_modules" not in key.split("/")}:
        _fail("LOCK_MEMBERSHIP_MISMATCH")
    return owners


def supported_workspace_npmrc(raw):
    # This setting changes how npm saves selectors, not how frozen ci resolves them.
    return raw in (b"save-exact=true", b"save-exact=true\n", b"save-exact=true\r\n")


def guard_workspace_npmrc(project, plan):
    path = project / ".npmrc"
    expected = plan.get("rootNpmrcSha256")
    if not path.exists() and not path.is_symlink():
        if expected is not None:
            _fail("INSTALL_NPMRC_DRIFT")
        return
    if expected is None:
        _fail("INSTALL_NPMRC_UNSUPPORTED")
    info = path.lstat()
    if (is_reparse(path) or getattr(info, "st_file_attributes", 0) & 0x400
            or not path.is_file() or info.st_size > 32):
        _fail("INSTALL_NPMRC_UNSUPPORTED")
    raw = path.read_bytes()
    if not supported_workspace_npmrc(raw) or _sha256_bytes(raw) != expected:
        _fail("INSTALL_NPMRC_DRIFT")


def compile_npm_workspace_obligations(baseline_lock, candidate_lock, candidate_manifests, resolver_record):
    """Use locally owned M3 evidence. A supplied digest alone grants no authority."""
    identity = resolver_record["identity"]
    receipt = resolver_record["receipt"]
    identity_digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    before, after = (_obligation_json(raw, 32 * 1024 * 1024) for raw in (baseline_lock, candidate_lock))
    if (receipt.get("authority") != "LOCKFILE_ONLY" or receipt.get("status") != "RESOLUTION_PASSED"
            or receipt.get("lockDelta", {}).get("code") != "LOCK_IMPACT_CLOSURE_MATCH"
            or receipt.get("resolverIdentitySha256") != identity_digest
            or receipt.get("baselineLockSha256") != _sha256_bytes(baseline_lock)
            or identity.get("baselineLockSha256") != receipt["baselineLockSha256"]
            or receipt.get("candidateLockSha256") != _sha256_bytes(candidate_lock)
            or any(lock.get("lockfileVersion") != 3 or "dependencies" in lock for lock in (before, after))):
        _fail("RESOLVER_EVIDENCE_UNBOUND")
    from workspace_npm_preflight import WORKSPACE_NPM_POLICY
    resolver_tools = {"nodeSha256": identity.get("nodeBinarySha256"), "npmCliSha256": identity.get("npmEntrypointSha256")}
    registry_digest = identity.get("registrySha256")
    if (any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value)
            for value in (*resolver_tools.values(), registry_digest))
            or identity.get("npmPolicy") != ["install", "--package-lock-only", *WORKSPACE_NPM_POLICY]):
        _fail("RESOLVER_POLICY_UNPROVEN")
    packages = after.get("packages")
    if (not isinstance(packages, dict) or not 2 <= len(packages) <= 10001
            or len({key.casefold() for key in packages}) != len(packages)
            or any(not isinstance(row, dict) for row in packages.values())):
        _fail("LOCK_GRAPH_UNPROVEN")
    owners = _owners(packages, identity.get("candidateManifestSha256"))
    if set(candidate_manifests) != set(identity["candidateManifestSha256"]):
        _fail("MANIFEST_SET_MISMATCH")
    owner_records = {}
    links = {}
    for owner, digest in sorted(owners.items()):
        raw = candidate_manifests[owner or "."]
        if _sha256_bytes(raw) != digest:
            _fail("MANIFEST_DRIFT")
        manifest = _obligation_json(raw, 2 * 1024 * 1024)
        _ordinary_npm_obligation_mode(manifest)
        declared = {key: manifest.get(key, {}) for key in SECTIONS}
        if any(not isinstance(value, dict) or packages[owner].get(key, {}) != value
               for key, value in declared.items()):
            _fail("MANIFEST_LOCK_MISMATCH")
        owner_records[owner] = {"manifestSha256": digest, "declarations": declared}
        if not owner:
            continue
        name = manifest.get("name")
        version = manifest.get("version")
        if not isinstance(name, str):
            _fail("LINK_NAME_UNPROVEN")
        slot = "node_modules/" + name
        _npm_obligation_name(slot, {"version": version})
        if (slot in links or packages[owner].get("name", name) != name
                or packages[owner].get("version") != version
                or packages.get(slot) != {"link": True, "resolved": owner}):
            _fail("LINK_TARGET_UNBOUND")
        links[slot] = {"owner": owner, "name": name, "version": version}

    instances = []
    for location in sorted(set(packages) - set(owners) - set(links)):
        record = packages[location]
        _ordinary_npm_obligation_mode(record)
        prefix, _, rest = ("/" + location).partition("/node_modules/")
        if not rest or prefix.strip("/") not in owners:
            _fail("INSTANCE_OWNER_UNBOUND")
        installed, canonical = _npm_obligation_name("node_modules/" + rest, record)
        instances.append({
            "path": location, "installName": installed, "name": canonical, "version": record["version"],
            "lockRecordDigest": _canonical_hash(record), "held": before["packages"].get(location) == record,
            "metadata": {key: record.get(key, {}) for key in INSTANCE_METADATA},
        })
    plan = {
        "schemaVersion": 1, "kind": WORKSPACE_OBLIGATION_KIND,
        "approvedLockSha256": receipt["candidateLockSha256"],
        "baselineLockSha256": receipt["baselineLockSha256"],
        "resolverIdentitySha256": identity_digest, "resolverToolchain": resolver_tools,
        "registrySha256": registry_digest,
        "rootDeclarations": owner_records[""]["declarations"],
        "workspaceOwners": owner_records, "workspaceLinks": links,
        "instances": instances,
        "changedInstanceCount": sum(before["packages"].get(path) != packages.get(path)
                                    for path in before["packages"].keys() | packages.keys()
                                    if path not in owners and path not in links),
    }
    if "rootNpmrcSha256" in identity:
        config_sha = identity["rootNpmrcSha256"]
        if not isinstance(config_sha, str) or not re.fullmatch(r"[a-f0-9]{64}", config_sha):
            _fail("INSTALL_NPMRC_UNSUPPORTED")
        plan["rootNpmrcSha256"] = config_sha
    return {**plan, "obligationPlanDigest": _canonical_hash(plan)}


def guard_workspace_install_inputs(project, plan, lock_bytes):
    """Refuse dependency trees or config that npm ci could remove or honor."""
    locked = _obligation_json(lock_bytes, 32 * 1024 * 1024)
    owners = plan["workspaceOwners"]
    _owners(locked["packages"], {owner or ".": row["manifestSha256"] for owner, row in owners.items()})

    def ordinary(path):
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if is_reparse(path) or getattr(info, "st_file_attributes", 0) & 0x400:
            _fail("INSTALL_REPARSE_UNPROVEN")
        return True

    guard_workspace_npmrc(project, plan)
    for owner, row in owners.items():
        directory = project
        for part in owner.split("/") if owner else ():
            directory /= part
            if not ordinary(directory) or not directory.is_dir():
                _fail("INSTALL_OWNER_UNPROVEN")
        manifest = directory / "package.json"
        if not ordinary(manifest) or not manifest.is_file() or manifest.stat().st_size > 2 * 1024 * 1024:
            _fail("MANIFEST_DRIFT")
        if _sha256_bytes(manifest.read_bytes()) != row["manifestSha256"]:
            _fail("MANIFEST_DRIFT")
        modules = directory / "node_modules"
        if ordinary(modules) and (not modules.is_dir() or any(modules.iterdir())):
            _fail("INSTALL_EXISTING_TREE_REQUIRES_RECOVERABLE_STAGING")
        if owner and ordinary(directory / ".npmrc"):
            _fail("INSTALL_NPMRC_UNSUPPORTED")
