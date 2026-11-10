"""Postconditions for a candidate npm workspace lock.

The result describes lockfile evidence. Installation and runtime checks are
separate and must observe the actual tree.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from semantic_version import NpmSpec, Version

from draft_npm_preflight import _npm_command
from verification_process_supervisor import ProcessSupervisionError, run_supervised

from project_runtime import normalize_npm_range
from resolution_inventory import npm_lock_resolved_instance, npm_lock_resolution_slots
from workspace_peer_model import Declaration
from workspace_glob import match_workspace_pattern
from workspace_npm_lock_delta import INSTALL_SECTIONS, check_workspace_lock_delta, peer_context


def check_workspace_lock(packages: dict, assignment: dict[Declaration, str], *, check_declared_peers=True) -> dict:
    evidence = {"authority": "LOCKFILE_ONLY", "installation": "NOT_RUN", "runtime": "NOT_RUN",
                "learningAllowed": False}
    for (owner, section, name), expected in sorted(assignment.items()):
        instance = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
        if instance is None or instance[1] != expected:
            return {**evidence, "status": "RESOLUTION_FAILED", "code": "LOCK_ASSIGNMENT_MISMATCH",
                    "declaration": [owner, section, name], "expectedVersion": expected,
                    "actualVersion": instance[1] if instance else None}
    if not check_declared_peers:
        return {**evidence, "status": "RESOLUTION_PASSED", "code": "LOCK_ASSIGNMENT_MATCH"}
    for consumer, entry in sorted(packages.items()):
        if not isinstance(entry, dict):
            return {**evidence, "status": "UNKNOWN", "code": "INVALID_LOCK_ENTRY"}
        if entry.get("link"):
            continue
        peers = entry.get("peerDependencies", {})
        peer_meta = entry.get("peerDependenciesMeta", {})
        installed_edges = [entry.get(section, {}) for section in ("dependencies", "optionalDependencies")]
        if not all(isinstance(value, dict) for value in [peers, peer_meta, *installed_edges]):
            return {**evidence, "status": "UNKNOWN", "code": "INVALID_LOCK_PEER_METADATA"}
        # Registry package peers resolve next to the consumer or above it.
        # Workspace manifests resolve relative to the real workspace directory.
        context = peer_context(consumer)
        for name, spec in sorted(peers.items()):
            # Arborist loads production and optional edges after peer edges.
            # npm's install verifies those effective non-peer edges separately.
            if any(name in dependencies for dependencies in installed_edges):
                continue
            flags = peer_meta.get(name, {})
            if not isinstance(spec, str) or not isinstance(flags, dict):
                return {**evidence, "status": "UNKNOWN", "code": "INVALID_LOCK_PEER_METADATA"}
            first_slot = next((slot for slot in npm_lock_resolution_slots(name, context) if slot in packages), None)
            provider = npm_lock_resolved_instance(packages, name, context)
            if first_slot is not None and (provider is None or provider[0] != first_slot):
                return {**evidence, "status": "UNKNOWN", "code": "LOCK_PEER_PROVIDER_VERSION_UNOBSERVED",
                        "consumer": consumer, "peer": name, "providerPath": first_slot}
            if provider is None and flags.get("optional") is True:
                continue
            try:
                required = NpmSpec(normalize_npm_range(spec))
            except ValueError:
                return {**evidence, "status": "UNKNOWN", "code": "UNSUPPORTED_LOCK_PEER_RANGE",
                        "consumer": consumer, "peer": name}
            try:
                valid = provider is not None and required.match(Version(provider[1]))
            except ValueError:
                return {**evidence, "status": "UNKNOWN", "code": "LOCK_PEER_PROVIDER_VERSION_UNOBSERVED",
                        "consumer": consumer, "peer": name, "providerPath": provider[0]}
            if not valid:
                return {**evidence, "status": "RESOLUTION_FAILED", "code": "LOCK_PEER_MISMATCH",
                        "consumer": consumer, "peer": name, "requiredRange": spec,
                        "providerPath": provider[0] if provider else None,
                        "providerVersion": provider[1] if provider else None}
    return {**evidence, "status": "RESOLUTION_PASSED", "code": "LOCK_ASSIGNMENT_AND_PEERS_MATCH"}

_SPEC = re.compile(r"[0-9A-Za-z.*+^~<>=| -]+")
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


_PACKAGE_NAME = r"(?:@[a-z0-9_~.-]+/)?[a-z0-9_~.-]+"
_OVERRIDE_SELECTOR = re.compile(rf"{_PACKAGE_NAME}(?:@([0-9A-Za-z.*+^~<>=| -]+))?")


def _check_root_overrides(project):
    """Allow registry specs and root references, without emulating npm's resolution."""
    declared = {name for section in (*INSTALL_SECTIONS, "peerDependencies")
                for name in project.get(section, {})}

    def check(rules, depth):
        if not isinstance(rules, dict) or depth > 16:
            raise ValueError("Unsupported npm overrides")
        for selector, value in rules.items():
            if selector == "." and depth > 0:
                if not isinstance(value, str):
                    raise ValueError("Invalid npm self override")
            elif not _OVERRIDE_SELECTOR.fullmatch(selector):
                raise ValueError("Invalid npm override selector")

            if isinstance(value, dict):
                check(value, depth + 1)
            elif not isinstance(value, str) or not (
                _SPEC.fullmatch(value) or (value.startswith("$") and re.fullmatch(_PACKAGE_NAME, value[1:])
                                      and value[1:] in declared)
            ):
                raise ValueError("Unsupported npm override spec")

    check(project["overrides"], 0)


WORKSPACE_NPM_POLICY = (
    "--package-lock=true", "--strict-peer-deps=true", "--engine-strict=true",
    "--ignore-scripts=true", "--force=false", "--legacy-peer-deps=false",
    "--install-strategy=hoisted", "--prefer-dedupe=false", "--no-audit", "--no-fund",
    "--global=false", "--workspaces=true", "--include-workspace-root=true",
    "--include=prod", "--include=dev", "--include=optional", "--include=peer",
    "--offline=true", "--prefer-offline=false",
)


# Resolve effective peers with the same npm distribution that authored the lock.
# Raw lock peer ranges can differ from effective edges after a root override.
_NATIVE_PEER_CHECK = """
const {createRequire} = require('node:module')
const Arborist = createRequire(process.argv[1])('@npmcli/arborist')
const packages = JSON.parse(require('node:fs').readFileSync('package-lock.json', 'utf8')).packages
async function inspect() {
  const root = await new Arborist({
    path: process.cwd(), offline: true, ignoreScripts: true,
    strictPeerDeps: true, legacyPeerDeps: false,
  }).loadVirtual()
  const nodeCount = root.inventory.size
  let unknown
  for (const node of root.inventory.values()) {
    for (const edge of node.edgesOut.values()) {
      if (!edge.peer) continue
      const provider = edge.to
      const record = provider && packages[provider.isLink ? provider.target?.location : provider.location]
      const witness = {consumer: node.location, peer: edge.name, requiredRange: edge.spec,
        providerPath: provider?.location ?? null, providerVersion: record?.version ?? null, nodeCount}
      if (provider && (typeof record?.version !== 'string' || !record.version)) {
        unknown ??= {status: 'UNKNOWN', code: 'LOCK_PEER_PROVIDER_VERSION_UNOBSERVED', ...witness}
      } else if (edge.error) {
        return {status: 'RESOLUTION_FAILED', code: 'LOCK_PEER_MISMATCH', ...witness}
      }
    }
  }
  return unknown ?? {status: 'RESOLUTION_PASSED', code: 'LOCK_ASSIGNMENT_AND_PEERS_MATCH', nodeCount}
}
inspect().then(row => console.log(JSON.stringify(row))).catch(() => {process.exitCode = 1})
"""


_OBSERVE_PEER_OVERRIDES = """
const {createRequire} = require('node:module')
const Arborist = createRequire(process.argv[1])('@npmcli/arborist')
new Arborist({path: process.cwd(), offline: true, ignoreScripts: true}).loadVirtual()
  .then(root => {
    const rows = []
    for (const node of root.inventory.values()) {
      for (const edge of node.edgesOut.values()) {
        if (edge.peer && edge.spec !== edge.rawSpec)
          rows.push([node.location, node.version, edge.name, edge.rawSpec, edge.spec])
      }
    }
    console.log(JSON.stringify(rows))
  }).catch(() => { process.exitCode = 1 })
"""


class WorkspacePeerEvidenceError(ValueError):
    """The effective-peer observation failed without proving a conflict."""


def observe_workspace_peer_overrides(inputs, packages, mutable, *, timeout_seconds: int = 10):
    """Read effective peer ranges from a private copy of the bound npm inputs."""
    root = json.loads(inputs["package.json"])
    if not root.get("overrides"):
        return {}
    try:
        _check_root_overrides(root)
        mutable_root = {name for owner, _, name in mutable if owner == "."}
        def has_mutable_reference(rules):
            return any(
                has_mutable_reference(value) if isinstance(value, dict)
                else value.startswith("$") and value[1:] in mutable_root
                for value in rules.values()
            )
        if has_mutable_reference(root["overrides"]):
            raise WorkspacePeerEvidenceError("MUTABLE_OVERRIDE_REFERENCE")
        with tempfile.TemporaryDirectory(prefix="workspace-peer-overrides-") as temp:
            workspace = Path(temp)
            for name, raw in inputs.items():
                if name != "package-lock.json" and not name.endswith("package.json"):
                    continue
                relative = PurePosixPath(name)
                if (relative.is_absolute() or ".." in relative.parts or "\\" in name or ":" in name
                        or relative.name not in {"package.json", "package-lock.json"}):
                    raise WorkspacePeerEvidenceError("INVALID_WORKSPACE_INPUT_PATH")
                path = workspace.joinpath(*relative.parts)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            node, npm = _workspace_npm_command()
            observed = run_supervised(
                [node, "-e", _OBSERVE_PEER_OVERRIDES, npm], workspace,
                timeout_seconds=timeout_seconds, progress_label="Observe effective npm peers",
                base_env=isolated_workspace_npm_environment(os.environ), max_output_bytes=65536)
            if observed.returncode:
                raise WorkspacePeerEvidenceError("NPM_OBSERVER_FAILED")
            if getattr(observed, "output_truncated", False):
                raise WorkspacePeerEvidenceError("NPM_OBSERVER_OUTPUT_LIMIT")
            rows = json.loads(observed.stdout)
            if not isinstance(rows, list):
                raise WorkspacePeerEvidenceError("INVALID_NPM_OBSERVER_OUTPUT")
        evidence = {}
        for path, version, peer, raw, effective in rows:
            row = packages.get(path)
            key = (path, version, peer, raw)
            if (not row or row.get("version") != version or row.get("peerDependencies", {}).get(peer) != raw
                    or not isinstance(effective, str) or key in evidence):
                raise WorkspacePeerEvidenceError("EFFECTIVE_PEER_LOCK_MISMATCH")
            NpmSpec(normalize_npm_range(effective))
            evidence[key] = effective
        return evidence
    except WorkspacePeerEvidenceError:
        raise
    except subprocess.TimeoutExpired:
        raise WorkspacePeerEvidenceError("NPM_OBSERVER_TIMEOUT") from None
    except ProcessSupervisionError:
        raise WorkspacePeerEvidenceError("NPM_OBSERVER_SUPERVISION_UNAVAILABLE") from None
    except (OSError, subprocess.SubprocessError):
        raise WorkspacePeerEvidenceError("NPM_OBSERVER_IO_UNAVAILABLE") from None
    except (ValueError, KeyError, TypeError):
        raise WorkspacePeerEvidenceError("INVALID_NPM_PEER_EVIDENCE") from None


def _workspace_npm_command():
    configured = os.environ.get("DEPLOOM_WORKSPACE_NPM_ENTRYPOINT")
    if configured is None:
        return _npm_command()
    entrypoint = Path(configured)
    node = shutil.which("node")
    if not node or not entrypoint.is_absolute() or entrypoint.name != "npm-cli.js" or not entrypoint.is_file():
        raise OSError("Configured workspace npm entrypoint is unavailable")
    return [node, str(entrypoint.resolve())]


def isolated_workspace_npm_environment(environment):
    return {key: value for key, value in environment.items()
            if not key.upper().startswith(("NPM_CONFIG_", "NODE_", "NPM_PACKAGE_", "NPM_LIFECYCLE_"))}


def run_workspace_npm_preflight(
    manifests: dict[str, bytes],
    baseline_lock: bytes,
    assignment: dict[Declaration, str],
    mutable: frozenset[Declaration],
    *,
    artifacts: Path,
    cache: Path,
    registry: str,
    timeout_seconds: int = 60,
    reauthor: Declaration | None = None,
    immutable_instances: frozenset[str] = frozenset(),
    root_npmrc: bytes | None = None,
) -> dict:
    """Check a hash-bound candidate with npm in an isolated, offline directory."""
    evidence = {"authority": "LOCKFILE_ONLY", "installation": "NOT_RUN", "runtime": "NOT_RUN",
                "learningAllowed": False, "lockMode": "PRESERVE_BASELINE"}
    if (not 1 <= timeout_seconds <= 60 or not 1 <= len(manifests) <= 256
            or "." not in manifests or not mutable <= assignment.keys()):
        return {**evidence, "status": "UNKNOWN", "code": "INVALID_WORKSPACE_PREFLIGHT_INPUT"}

    if root_npmrc is not None:
        from workspace_npm_obligations import supported_workspace_npmrc
        if not supported_workspace_npmrc(root_npmrc):
            return {**evidence, "status": "UNKNOWN", "code": "WORKSPACE_PREFLIGHT_PROJECT_NPMRC_UNSUPPORTED"}

    try:
        projects = {owner: json.loads(raw) for owner, raw in manifests.items()}
        lock = json.loads(baseline_lock)
        packages = lock["packages"]
        if lock["lockfileVersion"] != 3 or not isinstance(packages, dict):
            raise ValueError("Expected npm v3 lock")
        patterns = projects["."].get("workspaces")
        owners = projects.keys() - {"."}
        if (not isinstance(patterns, list) or not 1 <= len(patterns) <= 128
                or any(not isinstance(pattern, str) or not re.fullmatch(r"[A-Za-z0-9_./*-]+", pattern)
                       or "**" in pattern or any(part in {"", ".", "..", "node_modules", ".git"}
                                                for part in pattern.split("/"))
                       for pattern in patterns)
                or any(not any(match_workspace_pattern(owner, pattern) for owner in owners)
                       for pattern in patterns)
                or any(not any(match_workspace_pattern(owner, pattern) for pattern in patterns)
                       for owner in owners)):
            raise ValueError("Unproven workspace membership")
        lock_owners = {key for key in packages if key and "node_modules" not in key.split("/")}
        if lock_owners != owners:
            raise ValueError("Workspace membership differs from lock")
        for owner, project in projects.items():
            if (owner != "." and (not re.fullmatch(r"[A-Za-z0-9_./-]+", owner)
                    or PurePosixPath(owner).is_absolute()
                    or any(part in {"", ".", "..", "node_modules", ".git"} for part in owner.split("/")))):
                raise ValueError("Unsafe workspace owner")
            if not isinstance(project, dict) or (owner != "." and "overrides" in project):
                raise ValueError("Unsupported manifest")
            record = packages["" if owner == "." else owner]
            if any(project.get(section, {}) != record.get(section, {})
                   for section in (*INSTALL_SECTIONS, "peerDependencies")):
                raise ValueError("Manifest and lock disagree")
            for section in (*INSTALL_SECTIONS, "peerDependencies"):
                for spec in project.get(section, {}).values():
                    if not isinstance(spec, str) or not _SPEC.fullmatch(spec):
                        raise ValueError("Unsupported dependency spec")
        if "overrides" in projects["."]:
            _check_root_overrides(projects["."])
        for path, row in packages.items():
            if path and (not re.fullmatch(r"[A-Za-z0-9_./@+-]+", path)
                         or any(part in {"", ".", "..", ".git"} for part in path.split("/"))):
                raise ValueError("Unsafe lock entry")
            if not isinstance(row, dict):
                raise ValueError("Invalid lock entry")
            resolved = row.get("resolved")
            if row.get("link"):
                if resolved not in manifests or resolved == ".":
                    raise ValueError("Foreign workspace link")
            elif resolved is not None:
                url = urlsplit(resolved)
                if url.scheme != "https" or not url.hostname or url.username or url.password:
                    raise ValueError("Unsupported lock artifact")

        if (not isinstance(immutable_instances, frozenset) or len(immutable_instances) > 128
                or any(not isinstance(path, str) or "node_modules" not in path.split("/")
                       or path not in packages or packages[path].get("link")
                       or any(not isinstance(packages[path].get(field), str) or not packages[path][field]
                              for field in ("version", "resolved", "integrity"))
                       for path in immutable_instances)):
            return {**evidence, "status": "UNKNOWN", "code": "INVALID_IMMUTABLE_LOCK_INSTANCE"}

        observed = {(owner, section, name) for owner, project in projects.items()
                    for section in INSTALL_SECTIONS for name in project.get(section, {})}
        if observed != assignment.keys():
            raise ValueError("Incomplete owner assignment")
        manifest_deltas = {}
        changed = set()
        for key, expected in assignment.items():
            owner, section, name = key
            instance = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
            if instance is None:
                raise ValueError("Unproven baseline resolution")
            if expected != instance[1]:
                if key not in mutable or not _VERSION.fullmatch(expected) or packages[instance[0]].get("link"):
                    return {**evidence, "status": "RESOLUTION_FAILED", "code": "UNAUTHORIZED_DECLARATION_DELTA",
                            "declaration": list(key)}
                projects[owner][section][name] = expected
                lock_owner = "" if owner == "." else owner
                manifest_deltas.setdefault(lock_owner, {}).setdefault(section, {})[name] = expected
                changed.add(key)
    except (AttributeError, KeyError, TypeError, ValueError):
        return {**evidence, "status": "UNKNOWN", "code": "INVALID_WORKSPACE_PREFLIGHT_INPUT"}

    try:
        artifacts.mkdir(parents=True, exist_ok=True)
        workspace = Path(tempfile.mkdtemp(prefix="workspace-npm-", dir=artifacts))
        candidate_manifests = {}
        for owner, project in projects.items():
            path = workspace / owner / "package.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = manifests[owner]
            if project != json.loads(raw):
                raw = (json.dumps(project, indent=2) + "\n").encode("utf-8")
            path.write_bytes(raw)
            candidate_manifests[path] = raw
        lock_path = workspace / "package-lock.json"
        lock_path.write_bytes(baseline_lock)
        if root_npmrc is not None:
            (workspace / ".npmrc").write_bytes(root_npmrc)
        node, npm_cli = _workspace_npm_command()
        user_config = workspace / "user.npmrc"
        global_config = workspace / "global.npmrc"
        for config in (user_config, global_config):
            config.touch(exist_ok=False)
        npm_env = isolated_workspace_npm_environment(os.environ)
        identity = {
            "baselineLockSha256": hashlib.sha256(baseline_lock).hexdigest(),
            "sourceManifestSha256": {owner: hashlib.sha256(raw).hexdigest()
                                     for owner, raw in sorted(manifests.items())},
            "candidateManifestSha256": {
                path.parent.relative_to(workspace).as_posix(): hashlib.sha256(raw).hexdigest()
                for path, raw in candidate_manifests.items()
            },
            "assignment": [[*key, value] for key, value in sorted(assignment.items())],
            "mutable": [list(key) for key in sorted(mutable)],
            "reauthor": list(reauthor) if reauthor is not None else None,
            "registrySha256": hashlib.sha256(registry.encode()).hexdigest(),
        }
        if root_npmrc is not None:
            identity["rootNpmrcSha256"] = hashlib.sha256(root_npmrc).hexdigest()
        has_overrides = bool(projects["."].get("overrides"))
        if has_overrides:
            identity["peerEvidenceMethod"] = "NPM_EFFECTIVE_VIRTUAL_EDGES"
        if immutable_instances:
            identity["immutableInstances"] = sorted(immutable_instances)
        for label, executable in (("nodeBinarySha256", node), ("npmEntrypointSha256", npm_cli)):
            with Path(executable).open("rb") as stream:
                identity[label] = hashlib.file_digest(stream, "sha256").hexdigest()
        argv = [node, npm_cli,
            "install", "--package-lock-only", *WORKSPACE_NPM_POLICY, "--registry", registry, "--cache", str(cache),
            "--userconfig", str(user_config), "--globalconfig", str(global_config),
        ]
        # Record only deterministic policy flags. Registry, cache and config paths stay local.
        identity["npmPolicy"] = argv[2:argv.index("--registry")]
        identity_digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        deadline = time.monotonic() + timeout_seconds
        attempts = []

        def resolve(label):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout_seconds)
            proc = run_supervised(argv, workspace, timeout_seconds=remaining,
                                  progress_label=f"Workspace npm resolution: {label}", base_env=npm_env)
            output = proc.stdout or ""
            log = workspace / f"{label}.log"
            log.write_text(output, encoding="utf-8")
            attempts.append({"phase": label, "npmExitCode": proc.returncode,
                             "outputSha256": hashlib.sha256(log.read_bytes()).hexdigest()})
            match = re.search(r"npm (?:error|ERR!) code ([A-Z][A-Z0-9_]+)", output)
            return proc.returncode, match.group(1) if match else "NPM_RESOLUTION_ERROR"

        def check(exit_code, code):
            if exit_code:
                status = "RESOLUTION_FAILED" if code in {"ERESOLVE", "EBADENGINE", "EOVERRIDE"} else "UNKNOWN"
                return {"status": status, "code": code}
            packages = json.loads(lock_path.read_bytes())["packages"]
            result = check_workspace_lock(packages, assignment, check_declared_peers=False)
            if result["status"] != "RESOLUTION_PASSED":
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout_seconds)
            observed = run_supervised([node, "-e", _NATIVE_PEER_CHECK, npm_cli], workspace,
                                      timeout_seconds=remaining, progress_label="Workspace effective npm peers",
                                      base_env=npm_env, max_output_bytes=8192)
            unknown = {"status": "UNKNOWN", "code": "NPM_VIRTUAL_PEER_EVIDENCE_UNAVAILABLE"}
            if observed.returncode:
                return unknown
            try:
                native = json.loads(observed.stdout)
                if native["nodeCount"] != len(packages):
                    return unknown
                if (native["status"], native["code"]) in {
                    ("RESOLUTION_FAILED", "LOCK_PEER_MISMATCH"),
                    ("UNKNOWN", "LOCK_PEER_PROVIDER_VERSION_UNOBSERVED"),
                } and native["consumer"] in packages:
                    return native
                if (native["status"], native["code"]) == ("RESOLUTION_PASSED", "LOCK_ASSIGNMENT_AND_PEERS_MATCH"):
                    return {**result, "code": native["code"]}
            except (KeyError, TypeError, ValueError):
                pass
            return unknown

        reauthored = None
        exit_code, code = resolve("npm-resolution")
        result = check(exit_code, code)
        if (reauthor is not None and reauthor in assignment and reauthor not in mutable
                and result["code"] == "LOCK_PEER_MISMATCH"):
            owner, section, name = reauthor
            resolved = json.loads(lock_path.read_bytes())["packages"]
            instance = npm_lock_resolved_instance(resolved, name, "" if owner == "." else owner)
            same_slot = [
                key for key in assignment if key[2] == name and
                npm_lock_resolved_instance(resolved, name, "" if key[0] == "." else key[0]) == instance
            ]
            if (instance is not None and result["consumer"] == instance[0]
                    and same_slot == [reauthor] and projects[owner][section][name] == assignment[reauthor]
                    and _VERSION.fullmatch(assignment[reauthor]) and not resolved[instance[0]].get("link")):
                reauthored = reauthor
                attempts[-1].update(status=result["status"], code=result["code"])
                path = workspace / owner / "package.json"
                before = path.read_bytes()
                intermediate = json.loads(before)
                del intermediate[section][name]
                try:
                    path.write_text(json.dumps(intermediate, indent=2) + "\n", encoding="utf-8")
                    exit_code, code = resolve("reauthor-remove")
                finally:
                    path.write_bytes(before)
                if exit_code:
                    result = check(exit_code, code)
                else:
                    exit_code, code = resolve("reauthor-restore")
                    result = check(exit_code, code)
        if (any(path.read_bytes() != raw for path, raw in candidate_manifests.items())
                or root_npmrc is not None and (workspace / ".npmrc").read_bytes() != root_npmrc):
            result = {"status": "UNKNOWN", "code": "CANDIDATE_MANIFEST_CHANGED"}
        if result["status"] == "RESOLUTION_PASSED":
            delta = check_workspace_lock_delta(
                lock, json.loads(lock_path.read_bytes()), manifest_deltas, assignment, changed, reauthored,
                immutable_instances)
            if delta["status"] != "RESOLUTION_PASSED":
                result.update(status=delta["status"], code=delta["code"])
            result["lockDelta"] = delta
        if immutable_instances:
            result["immutableInstanceCount"] = len(immutable_instances)
        receipt = {**evidence, **result, "npmExitCode": exit_code, "attempts": attempts,
                   "baselineLockSha256": identity["baselineLockSha256"],
                   "candidateLockSha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
                   "resolverIdentitySha256": identity_digest}
        with (workspace / "receipt.json").open("x", encoding="utf-8") as stream:
            json.dump({"identity": identity, "receipt": receipt}, stream, indent=2)
        return {**receipt, "workspace": str(workspace)}
    except subprocess.TimeoutExpired:
        return {**evidence, "status": "UNKNOWN", "code": "RESOLVER_TIMEOUT"}
    except (AttributeError, OSError, ValueError, KeyError, TypeError):
        return {**evidence, "status": "UNKNOWN", "code": "RESOLVER_EVIDENCE_UNAVAILABLE"}
