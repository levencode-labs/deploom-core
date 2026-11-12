"""Protect npm's physical preparation and proof publication boundary."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import baseline_constraint_verifier as verifier
from verification_proof import VerificationProofStore, build_resolver_context_key


class NpmLockOnlyPreparationTests(unittest.TestCase):
    def setUp(self):
        if not verifier.resolve_executable("npm") or not verifier.resolve_executable("node"):
            self.skipTest("Node and npm are required")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.project = root / "source"
        self.project.mkdir()
        manifest = {"name": "lock-only-preparation-fixture", "version": "1.0.0"}
        lock = {**manifest, "lockfileVersion": 3, "requires": True, "packages": {"": manifest}}
        for filename, value in (("package.json", manifest), ("package-lock.json", lock)):
            (self.project / filename).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        (self.project / "verify.cjs").write_text("require('./package.json');\n", encoding="utf-8")
        self.config = verifier.BaselineVerifyConfig(
            commands=("node verify.cjs",), project_checks="strict", lifecycle_scripts=False,
            timeout_seconds=30, attempt_timeout_seconds=60,
            proof_cache_dir=str(root / "proofs"), verification_purpose="intermediate-candidate",
        )
        environment = patch.dict(os.environ, {
            "DEPLOOM_VERIFICATION_ROOT": str(root / "storage"),
            "npm_config_cache": str(root / "npm-cache"),
            "npm_config_offline": "true",
        })
        environment.start()
        self.addCleanup(environment.stop)

    def add_pinned_workspace(self):
        package = self.project / "packages" / "demo"
        package.mkdir(parents=True)
        demo = {"name": "demo", "version": "1.0.0"}
        (package / "package.json").write_text(json.dumps(demo), encoding="utf-8")
        root_manifest = self.project / "package.json"
        manifest = json.loads(root_manifest.read_bytes())
        manifest.update(workspaces=["packages/demo"], dependencies={"demo": "1.0.0"})
        root_manifest.write_text(json.dumps(manifest), encoding="utf-8")
        lock_path = self.project / "package-lock.json"
        lock = json.loads(lock_path.read_bytes())
        lock["packages"] = {
            "": manifest, "node_modules/demo": {"resolved": "packages/demo", "link": True},
            "packages/demo": {"version": "1.0.0"},
        }
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        return {"demo": "1.0.0"}

    def run_case(self, *, checks, reject_frozen=False, assignment=None, omit_payload=False):
        steps = []
        install = verifier._run_preparation_install
        publish = VerificationProofStore.publish_pass

        def observe_install(argv, cwd, **kwargs):
            args = " ".join(argv).split()
            if "ci" in args:
                steps.append("frozen-install")
                if reject_frozen:
                    return subprocess.CompletedProcess(argv, 1, "npm ERR! code EUSAGE")
                if omit_payload:
                    return subprocess.CompletedProcess(argv, 0, "")
            else:
                steps.append("lock-only" if "--package-lock-only" in args else "physical-resolver")
            return install(argv, cwd, **kwargs)

        def observe_publish(store, proof_type, *args, **kwargs):
            steps.append(f"publish-{proof_type}")
            return publish(store, proof_type, *args, **kwargs)

        with patch.object(verifier, "_run_preparation_install", side_effect=observe_install), patch.object(
            VerificationProofStore, "publish_pass", autospec=True, side_effect=observe_publish
        ):
            result = verifier.verify_assignment(self.project, assignment or {}, config=self.config, run_project_checks=checks)
        return result, steps

    def test_already_edited_candidate_publishes_after_frozen_install(self):
        result, steps = self.run_case(checks=True)
        self.assertTrue(result.ok, (result.summary, result.output))
        self.assertEqual(steps[:4], ["lock-only", "frozen-install", "publish-resolver", "publish-preparation"])

    def test_failed_frozen_install_cannot_publish_resolver_proof(self):
        result, steps = self.run_case(checks=True, reject_frozen=True)
        self.assertFalse(result.ok)
        self.assertEqual(steps, ["lock-only", "frozen-install"])

    def test_pre_applied_exact_pin_is_confirmed_in_npm_ci_tree(self):
        assignment = self.add_pinned_workspace()
        result, steps = self.run_case(checks=True, assignment=assignment)
        self.assertTrue(result.ok, (result.summary, result.output))
        self.assertEqual(result.observed_resolved_versions, assignment)
        self.assertEqual(steps[:4], ["lock-only", "frozen-install", "publish-resolver", "publish-preparation"])

    def test_pre_applied_exact_pin_requires_installed_payload(self):
        assignment = self.add_pinned_workspace()
        result, steps = self.run_case(checks=True, assignment=assignment, omit_payload=True)
        self.assertFalse(result.ok)
        self.assertIn("OBSERVED_RESOLVED_ASSIGNMENT_MISSING", result.summary)
        self.assertEqual(steps, ["lock-only", "frozen-install"])

    def test_global_npm_config_bytes_participate_in_resolver_identity(self):
        npmrc = self.project.parent / "global.npmrc"
        environment = {**os.environ, "npm_config_globalconfig": str(npmrc)}
        arguments = {
            "manager": "npm", "manager_executable": verifier.resolve_executable("npm"),
            "registry": "", "environment": environment,
        }
        npmrc.write_text("omit=optional\n", encoding="utf-8")
        before = build_resolver_context_key(self.project, **arguments)
        npmrc.write_text("include=optional\n", encoding="utf-8")
        after = build_resolver_context_key(self.project, **arguments)
        self.assertNotEqual(before, after)

    def test_resolver_only_check_still_materializes(self):
        result, steps = self.run_case(checks=False)
        self.assertTrue(result.ok, (result.summary, result.output))
        self.assertEqual(steps, ["physical-resolver", "publish-resolver"])
