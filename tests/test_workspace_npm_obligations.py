import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from reparse_materialization import _create_junction
from resolved_dependency_state import MaterializedDependencyObligationError, observe_npm_dependency_obligations
from workspace_npm_obligations import compile_npm_workspace_obligations, guard_workspace_install_inputs
from workspace_npm_preflight import WORKSPACE_NPM_POLICY


def encode(value):
    return json.dumps(value, sort_keys=True).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class WorkspacePhysicalTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        root = {"name": "control", "version": "1.0.0", "workspaces": ["apps/*"],
                "dependencies": {"a": "1.0.0", "react": "19.0.0"}}
        member = {"name": "a", "version": "1.0.0", "dependencies": {"react": "18.3.1"},
                  "peerDependencies": {"optional": "*"}, "peerDependenciesMeta": {"optional": {"optional": True}}}
        self.manifests = {".": encode(root), "apps/a": encode(member)}
        self.packages = {"": root, "apps/a": member, "node_modules/a": {"link": True, "resolved": "apps/a"},
                         "node_modules/react": {"version": "19.0.0"},
                         "apps/a/node_modules/react": {"version": "18.3.1"}}
        self.lock = encode({"lockfileVersion": 3, "packages": self.packages})
        self.identity = {"baselineLockSha256": digest(self.lock), "registrySha256": "c" * 64,
                         "nodeBinarySha256": "d" * 64, "npmEntrypointSha256": "e" * 64,
                         "npmPolicy": ["install", "--package-lock-only", *WORKSPACE_NPM_POLICY],
                         "candidateManifestSha256": {owner: digest(raw) for owner, raw in self.manifests.items()}}
        self.record = {"identity": self.identity, "receipt": {
            "authority": "LOCKFILE_ONLY", "status": "RESOLUTION_PASSED",
            "baselineLockSha256": digest(self.lock), "candidateLockSha256": digest(self.lock),
            "resolverIdentitySha256": digest(encode(self.identity)),
            "lockDelta": {"code": "LOCK_IMPACT_CLOSURE_MATCH"},
        }}
        (self.root / "package-lock.json").write_bytes(self.lock)
        for owner, manifest in self.manifests.items():
            self.write(self.root / owner / "package.json", manifest)
        for location in ("node_modules/react", "apps/a/node_modules/react"):
            self.write(self.root / location / "package.json", encode({"name": "react", **self.packages[location]}))

    @staticmethod
    def write(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def link(self, owner):
        path = self.root / "node_modules/a"
        if os.name == "nt":
            _create_junction(path, self.root / owner)
        else:
            path.symlink_to(self.root / owner, target_is_directory=True)

    def observe(self):
        plan = compile_npm_workspace_obligations(self.lock, self.lock, self.manifests, self.record)
        return observe_npm_dependency_obligations(
            self.root, plan, source_origin_digest="a" * 64, resolved_state_key="b" * 64)

    def test_expected_link_and_nested_owner_resolve(self):
        self.link("apps/a")
        report = self.observe()
        self.assertEqual(report["workspaceOwnerCount"], 2)
        self.assertEqual(report["workspaceLinkCount"], 1)
        self.assertEqual(report["instanceCount"], 2)
        self.assertFalse(report["fullAcceptance"])

    def test_wrong_in_root_link_is_rejected(self):
        (self.root / "apps/other").mkdir()
        self.link("apps/other")
        with self.assertRaisesRegex(MaterializedDependencyObligationError, "WORKSPACE_LINK_MISMATCH"):
            self.observe()

    def test_owned_manifest_bytes_and_nested_version_are_guarded(self):
        self.link("apps/a")
        member = self.root / "apps/a/package.json"
        member.write_bytes(self.manifests["apps/a"] + b" ")
        with self.assertRaisesRegex(MaterializedDependencyObligationError, "MANIFEST_DRIFT"):
            self.observe()
        member.write_bytes(self.manifests["apps/a"])
        self.write(self.root / "apps/a/node_modules/react/package.json", encode({"name": "react", "version": "19.0.0"}))
        with self.assertRaisesRegex(MaterializedDependencyObligationError, "IDENTITY_MISMATCH"):
            self.observe()

    def test_existing_nested_tree_is_not_removable_by_frozen_install(self):
        plan = compile_npm_workspace_obligations(self.lock, self.lock, self.manifests, self.record)
        root_package = self.root / "node_modules/react/package.json"
        root_package.unlink()
        root_package.parent.rmdir()
        nested = self.root / "apps/a/node_modules/react/package.json"
        original = nested.read_bytes()
        with self.assertRaisesRegex(MaterializedDependencyObligationError, "EXISTING_TREE_REQUIRES_RECOVERABLE_STAGING"):
            guard_workspace_install_inputs(self.root, plan, self.lock)
        self.assertEqual(nested.read_bytes(), original)

    def test_frozen_install_requires_exact_bound_root_npmrc(self):
        for location in ("node_modules/react", "apps/a/node_modules/react"):
            (self.root / location / "package.json").unlink()
            (self.root / location).rmdir()
        config = self.root / ".npmrc"
        config.write_bytes(b"save-exact=true\n")
        unbound = compile_npm_workspace_obligations(self.lock, self.lock, self.manifests, self.record)
        with self.assertRaisesRegex(MaterializedDependencyObligationError, "INSTALL_NPMRC_UNSUPPORTED"):
            guard_workspace_install_inputs(self.root, unbound, self.lock)
        self.identity["rootNpmrcSha256"] = digest(config.read_bytes())
        self.record["receipt"]["resolverIdentitySha256"] = digest(encode(self.identity))
        plan = compile_npm_workspace_obligations(self.lock, self.lock, self.manifests, self.record)
        self.assertEqual(self.identity["rootNpmrcSha256"], plan["rootNpmrcSha256"])
        guard_workspace_install_inputs(self.root, plan, self.lock)

        for replacement in (b"save-exact=true\r\n", b"save-exact=false\n"):
            config.write_bytes(replacement)
            with self.assertRaisesRegex(MaterializedDependencyObligationError, "INSTALL_NPMRC_DRIFT"):
                guard_workspace_install_inputs(self.root, plan, self.lock)
        config.unlink()
        with self.assertRaisesRegex(MaterializedDependencyObligationError, "INSTALL_NPMRC_DRIFT"):
            guard_workspace_install_inputs(self.root, plan, self.lock)

    def test_receipt_is_bound_to_exact_candidate_lock(self):
        with self.assertRaisesRegex(MaterializedDependencyObligationError, "RESOLVER_EVIDENCE_UNBOUND"):
            compile_npm_workspace_obligations(self.lock, self.lock + b" ", self.manifests, self.record)
