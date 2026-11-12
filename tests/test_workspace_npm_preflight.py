import unittest

import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch
from workspace_npm_preflight import (
    WorkspacePeerEvidenceError, _workspace_npm_command, check_workspace_lock,
    observe_workspace_peer_overrides, run_workspace_npm_preflight,
)
from verification_process_supervisor import ProcessSupervisionError


class WorkspaceLockChecks(unittest.TestCase):
    def test_peer_observer_distinguishes_timeout_and_process_supervision(self):
        inputs = {"package.json": b'{"overrides":{"leaf":"1.0.0"}}'}
        failures = (
            (subprocess.TimeoutExpired(["private command"], 10), "NPM_OBSERVER_TIMEOUT"),
            (ProcessSupervisionError("private diagnostic"), "NPM_OBSERVER_SUPERVISION_UNAVAILABLE"),
        )
        for failure, expected in failures:
            with self.subTest(expected=expected), patch(
                "workspace_npm_preflight._workspace_npm_command", return_value=("node", "npm-cli.js"),
            ), patch("workspace_npm_preflight.run_supervised", side_effect=failure) as runner:
                with self.assertRaises(WorkspacePeerEvidenceError) as raised:
                    observe_workspace_peer_overrides(inputs, {}, {}, timeout_seconds=20)
                self.assertEqual(runner.call_args.kwargs["timeout_seconds"], 20)
                self.assertEqual(str(raised.exception), expected)
                self.assertIsNone(raised.exception.__cause__)

    def test_same_direct_versions_do_not_hide_incompatible_hoisted_peer(self):
        assignment = {
            (".", "dependencies", "react"): "19.0.0",
            ("packages/legacy", "dependencies", "react"): "18.3.1",
            ("packages/legacy", "dependencies", "react-dom"): "18.3.1",
        }
        renderer = {"version": "18.3.1", "peerDependencies": {"react": ">= 18.3.1 < 19"}}
        packages = {
            "node_modules/react": {"version": "19.0.0"},
            "packages/legacy/node_modules/react": {"version": "18.3.1"},
            "packages/legacy/node_modules/react-dom": renderer,
        }
        accepted = check_workspace_lock(packages, assignment)
        self.assertEqual(accepted["status"], "RESOLUTION_PASSED")
        self.assertEqual(accepted["installation"], "NOT_RUN")

        packages["node_modules/react-dom"] = packages.pop("packages/legacy/node_modules/react-dom")
        rejected = check_workspace_lock(packages, assignment)
        self.assertEqual(rejected["code"], "LOCK_PEER_MISMATCH")
        self.assertEqual(rejected["providerVersion"], "19.0.0")
        self.assertFalse(rejected["learningAllowed"])

    def test_absent_optional_peer_allowed_but_incompatible_present_peer_rejected(self):
        packages = {"node_modules/consumer": {
            "version": "1.0.0", "peerDependencies": {"react": "^18"},
            "peerDependenciesMeta": {"react": {"optional": True}},
        }}
        self.assertEqual(check_workspace_lock(packages, {})["status"], "RESOLUTION_PASSED")
        packages["node_modules/react"] = {"version": "19.0.0"}
        self.assertEqual(check_workspace_lock(packages, {})["code"], "LOCK_PEER_MISMATCH")


    def test_prod_edge_shadows_peer_with_same_name(self):
        packages = {
            "node_modules/consumer": {"version": "1.0.0", "dependencies": {"ajv": "^8"},
                                      "peerDependencies": {"ajv": "^8"}},
            "node_modules/consumer/node_modules/ajv": {"version": "8.20.0"},
            "node_modules/ajv": {"version": "6.15.0"},
        }
        self.assertEqual(check_workspace_lock(packages, {})["status"], "RESOLUTION_PASSED")
        del packages["node_modules/consumer"]["dependencies"]
        self.assertEqual(check_workspace_lock(packages, {})["code"], "LOCK_PEER_MISMATCH")

    def test_unobserved_nearest_peer_does_not_fall_back_or_become_absent(self):
        packages = {
            "packages/app/node_modules/consumer": {"version": "1.0.0", "peerDependencies": {"host": "^1"},
                                                   "peerDependenciesMeta": {"host": {"optional": True}}},
            "packages/app/node_modules/host": {"resolved": "https://registry.npmjs.org/host/-/host.tgz"},
            "node_modules/host": {"version": "1.0.0"},
        }
        result = check_workspace_lock(packages, {})
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["code"], "LOCK_PEER_PROVIDER_VERSION_UNOBSERVED")
        self.assertEqual(result["providerPath"], "packages/app/node_modules/host")

    def test_protected_assignment_change_is_rejected_before_npm(self):
        projects = {
            ".": {"workspaces": ["packages/*"]},
            "packages/legacy": {"dependencies": {"react": "18.3.1"}},
        }
        lock = {"lockfileVersion": 3, "packages": {
            "": projects["."],
            "packages/legacy": projects["packages/legacy"],
            "node_modules/react": {"version": "18.3.1"},
        }}
        inputs = {owner: json.dumps(manifest).encode() for owner, manifest in projects.items()}
        with patch("workspace_npm_preflight.run_supervised") as runner:
            result = run_workspace_npm_preflight(
                inputs, json.dumps(lock).encode(), {("packages/legacy", "dependencies", "react"): "19.0.0"},
                frozenset(), artifacts=Path("unused"), cache=Path("unused"), registry="https://registry.npmjs.org/",
            )
        runner.assert_not_called()
        self.assertEqual(result["code"], "UNAUTHORIZED_DECLARATION_DELTA")

    def test_fixed_root_peer_conflicts_are_reported_without_npm(self):
        root = {"workspaces": ["packages/*"],
                "dependencies": {"peer": "1.0.0", "consumer": "1.0.0", "second": "1.0.0"}}
        member = {"name": "app", "version": "1.0.0"}
        consumer = {"version": "1.0.0", "peerDependencies": {"peer": "^1 || ^2"}}
        lock = {"lockfileVersion": 3, "packages": {
            "": root, "packages/app": member, "node_modules/peer": {"version": "1.0.0"},
            "node_modules/consumer": consumer, "node_modules/second": consumer,
        }}
        inputs = {".": json.dumps(root).encode(), "packages/app": json.dumps(member).encode()}
        assignment = {(".", "dependencies", name): version for name, version in root["dependencies"].items()}
        target = (".", "dependencies", "peer")
        assignment[target] = "2.0.0"
        with patch("workspace_npm_preflight._workspace_npm_command") as npm:
            result = run_workspace_npm_preflight(
                inputs, json.dumps(lock).encode(), assignment, frozenset({target}),
                artifacts=Path("unused"), cache=Path("unused"), registry="https://registry.npmjs.org/",
            )
        npm.assert_not_called()
        self.assertEqual(result["code"], "HELD_LOCK_PROVIDER_CHANGED")
        self.assertEqual(result["phase"], "BASELINE_ROOT_PEER_CHECK")
        self.assertEqual(result["attempts"], [])
        self.assertEqual(result["conflictCount"], 2)
        self.assertEqual([row["path"] for row in result["heldConflicts"]],
                         ["node_modules/consumer", "node_modules/second"])
        self.assertEqual((result["dependency"], result["beforeVersion"], result["requestedVersion"]),
                         ("peer", "1.0.0", "2.0.0"))

    def test_held_root_peer_rejects_all_changed_versions_only_when_proved(self):
        from workspace_npm_lock_delta import forced_root_peer_domain_conflicts

        graph = {
            "": {"dependencies": {"provider": "1.0.0", "consumer": "1.0.0", "shadowed": "1.0.0"}},
            "node_modules/provider": {"version": "1.0.0"},
            "node_modules/consumer": {"version": "1.0.0", "peerDependencies": {"provider": "*"}},
            "node_modules/shadowed": {"version": "1.0.0", "peerDependencies": {"provider": "*"},
                                      "dependencies": {"provider": "1.0.0"}},
        }
        alternatives = ("2.0.0", "2.1.0")
        self.assertEqual(forced_root_peer_domain_conflicts(graph, {"provider": alternatives}), [
            {"path": "node_modules/consumer", "dependency": "provider", "section": "peerDependencies",
             "beforeVersion": "1.0.0", "requestedVersion": "2.0.0", "requestedVersions": list(alternatives)},
        ])
        for domains in ({"provider": ("1.0.0", *alternatives)}, {"provider": ()},
                        {"provider": alternatives, "consumer": ()}):
            with self.subTest(domains=domains):
                self.assertEqual(forced_root_peer_domain_conflicts(graph, domains), [])

    def test_existing_root_overrides_reach_npm_unchanged(self):
        overrides = {"parent@^1": {".": "1.2.0", "@scope/child": "$@scope/child"}}
        root = {"workspaces": ["packages/*"], "dependencies": {"@scope/child": "1.0.0"},
                "overrides": overrides}
        member = {"name": "app", "version": "1.0.0"}
        baseline = {"lockfileVersion": 3, "packages": {
            "": {"workspaces": root["workspaces"], "dependencies": root["dependencies"]},
            "packages/app": member,
            "node_modules/@scope/child": {"version": "1.0.0"},
        }}
        inputs = {owner: json.dumps(project).encode() for owner, project in ((".", root), ("packages/app", member))}
        assignment = {(".", "dependencies", "@scope/child"): "1.0.0"}

        def resolve(argv, workspace, **kwargs):
            self.assertEqual(json.loads((workspace / "package.json").read_bytes())["overrides"], overrides)
            if argv[1] == "-e":
                return subprocess.CompletedProcess(argv, 0, json.dumps({
                    "status": "RESOLUTION_PASSED", "code": "LOCK_ASSIGNMENT_AND_PEERS_MATCH", "nodeCount": 3,
                }))
            self.assertEqual(argv[argv.index("--registry") + 1], "https://mirror.example.invalid/npm")
            self.assertIn("--strict-peer-deps=true", argv)
            return subprocess.CompletedProcess(argv, 0, "")

        with (tempfile.TemporaryDirectory() as temp,
              patch("workspace_npm_preflight._npm_command", return_value=[__file__, __file__]),
              patch("workspace_npm_preflight.run_supervised", side_effect=resolve) as runner):
            options = {"artifacts": Path(temp), "cache": Path(temp), "registry": "https://mirror.example.invalid/npm"}
            result = run_workspace_npm_preflight(inputs, json.dumps(baseline).encode(), assignment, frozenset(), **options)
            self.assertEqual(result["status"], "RESOLUTION_PASSED")
            self.assertEqual(result["runtime"], "NOT_RUN")
            for invalid in ({"parent": {"child": "$not-in-root"}},
                            {"parent": {"child": "https://example.invalid/archive.tgz"}},
                            {"parent@file:./x": "1.2.0"}):
                inputs["."] = json.dumps({**root, "overrides": invalid}).encode()
                result = run_workspace_npm_preflight(
                    inputs, json.dumps(baseline).encode(), assignment, frozenset(), **options)
                self.assertEqual(result["code"], "INVALID_WORKSPACE_PREFLIGHT_INPUT")
            self.assertEqual(runner.call_count, 2)

    def test_preflight_requires_effective_peers_without_overrides(self):
        root = {"workspaces": ["packages/*"]}
        member = {"name": "app", "version": "1.0.0"}
        lock = {"lockfileVersion": 3, "packages": {"": root, "packages/app": member}}
        inputs = {".": json.dumps(root).encode(), "packages/app": json.dumps(member).encode()}
        native = {"status": "UNKNOWN", "code": "LOCK_PEER_PROVIDER_VERSION_UNOBSERVED",
                  "consumer": "packages/app", "nodeCount": 2}
        with (tempfile.TemporaryDirectory() as temp,
              patch("workspace_npm_preflight._npm_command", return_value=[__file__, __file__]),
              patch("workspace_npm_preflight.run_supervised", side_effect=[
                  subprocess.CompletedProcess(["npm"], 0, ""),
                  subprocess.CompletedProcess(["node"], 0, json.dumps(native)),
              ]) as runner):
            result = run_workspace_npm_preflight(
                inputs, json.dumps(lock).encode(), {}, frozenset(),
                artifacts=Path(temp), cache=Path(temp), registry="https://registry.npmjs.org/",
            )
        self.assertEqual((result["status"], result["code"]),
                         ("UNKNOWN", "LOCK_PEER_PROVIDER_VERSION_UNOBSERVED"))
        self.assertEqual(runner.call_args.args[0][1], "-e")
        self.assertEqual(runner.call_count, 2)
        self.assertFalse(result["learningAllowed"])

    def test_host_pinned_npm_does_not_fall_back_to_path_npm(self):
        with (tempfile.TemporaryDirectory() as temp,
              patch("workspace_npm_preflight.shutil.which", return_value="node.exe"),
              patch("workspace_npm_preflight._npm_command") as default):
            entrypoint = Path(temp) / "npm-cli.js"
            entrypoint.touch()
            with patch.dict(os.environ, {"DEPLOOM_WORKSPACE_NPM_ENTRYPOINT": str(entrypoint)}):
                self.assertEqual(_workspace_npm_command(), ["node.exe", str(entrypoint.resolve())])
                entrypoint.unlink()
                with self.assertRaises(OSError):
                    _workspace_npm_command()
            default.assert_not_called()

    def test_native_timeout_is_unknown_and_never_learned(self):
        projects = {
            ".": {"workspaces": ["packages/*"], "dependencies": {"react": "18.3.1"}},
            "packages/app": {"name": "app", "version": "1.0.0"},
        }
        lock = {"lockfileVersion": 3, "packages": {
            "": projects["."], "packages/app": projects["packages/app"],
            "node_modules/react": {"version": "18.3.1"},
        }}
        inputs = {owner: json.dumps(manifest).encode() for owner, manifest in projects.items()}
        target = (".", "dependencies", "react")
        with (tempfile.TemporaryDirectory() as temp,
              patch("workspace_npm_preflight._npm_command", return_value=[__file__, __file__]),
              patch("workspace_npm_preflight.run_supervised", side_effect=subprocess.TimeoutExpired(["npm"], 1))):
            result = run_workspace_npm_preflight(
                inputs, json.dumps(lock).encode(), {target: "19.0.0"}, frozenset({target}),
                artifacts=Path(temp) / "artifacts", cache=Path(temp) / "cache",
                registry="https://registry.npmjs.org/", timeout_seconds=1,
            )
        self.assertEqual((result["status"], result["code"]), ("UNKNOWN", "RESOLVER_TIMEOUT"))
        self.assertFalse(result["learningAllowed"])
        self.assertEqual(result["installation"], "NOT_RUN")
