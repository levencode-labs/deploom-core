from copy import deepcopy
import unittest

from workspace_npm_lock_delta import check_workspace_lock_delta


class WorkspaceLockDeltaTests(unittest.TestCase):
    def setUp(self):
        self.target = (".", "dependencies", "target")
        self.held = ("app", "dependencies", "held")
        self.assignment = {self.target: "2.0.0", self.held: "1.0.0"}
        self.before = {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"target": "1.0.0"}},
            "app": {"dependencies": {"held": "1.0.0"}},
            "node_modules/app": {"link": True, "resolved": "app"},
            "node_modules/target": {"version": "1.0.0", "dependencies": {"related": "^1"}},
            "node_modules/related": {"version": "1.0.0"},
            "node_modules/held": {"version": "1.0.0", "integrity": "sha512-original",
                                  "dependencies": {"unrelated": "^1"}},
            "node_modules/unrelated": {"version": "1.0.0"},
        }}
        self.after = deepcopy(self.before)
        self.after["packages"][""]["dependencies"]["target"] = "2.0.0"
        self.after["packages"]["node_modules/target"] = {
            "version": "2.0.0", "dependencies": {"related": "^2"},
        }
        self.after["packages"]["node_modules/related"]["version"] = "2.0.0"

    def check(self, reauthored=None, pins=frozenset()):
        return check_workspace_lock_delta(
            self.before, self.after, {"": {"dependencies": {"target": "2.0.0"}}},
            self.assignment, {self.target}, reauthored, pins,
        )

    def test_related_transitive_delta_has_changed_dependency_edge(self):
        self.assertEqual(self.check(), {
            "status": "RESOLUTION_PASSED", "code": "LOCK_IMPACT_CLOSURE_MATCH",
            "changedPackageCount": 2, "changedEdgeCount": 2, "impactedInstanceCount": 2,
        })

    def test_explicit_immutable_instance_cannot_change_even_within_impact(self):
        result = self.check(pins=frozenset({"node_modules/related"}))
        self.assertEqual(result["code"], "IMMUTABLE_LOCK_INSTANCE_CHANGED")
        self.assertEqual(result["path"], "node_modules/related")

    def test_unrelated_transitive_change_is_rejected(self):
        self.after["packages"]["node_modules/unrelated"]["version"] = "1.1.0"
        self.assertEqual(self.check()["code"], "LOCK_UNRELATED_NODE_DELTA")
        self.assertEqual(self.check(self.held)["code"], "LOCK_UNRELATED_NODE_DELTA")

    def test_transitive_dev_flag_follows_proved_runtime_reachability(self):
        for lock in (self.before, self.after):
            packages = lock["packages"]
            packages[""]["devDependencies"] = {"compile-only": "1.0.0"}
            packages["node_modules/compile-only"] = {"version": "1.0.0", "dependencies": {"leaf": "^1"}}
            packages["node_modules/leaf"] = {"version": "1.0.0"}
        self.before["packages"]["node_modules/target"]["dependencies"]["compile-only"] = "^1"
        self.after["packages"]["node_modules/compile-only"]["dev"] = True
        self.after["packages"]["node_modules/leaf"]["dev"] = True
        self.assertEqual(self.check()["status"], "RESOLUTION_PASSED")

        self.after["packages"]["node_modules/leaf"]["dev"] = False
        result = self.check()
        self.assertEqual(result["code"], "LOCK_UNRELATED_NODE_DELTA")
        self.assertEqual(result["path"], "node_modules/leaf")

    def test_unchanged_runtime_reachability_cannot_authorize_dev_flip(self):
        self.after["packages"]["node_modules/unrelated"]["dev"] = True
        self.assertEqual(self.check()["code"], "LOCK_UNRELATED_NODE_DELTA")

    def test_held_artifact_cannot_change_at_same_version(self):
        self.after["packages"]["node_modules/held"]["integrity"] = "sha512-substituted"
        self.assertEqual(self.check(self.held)["code"], "HELD_LOCK_ARTIFACT_CHANGED")

    def prepare_held_relocation(self):
        old_path = "node_modules/held"
        new_path = "app/node_modules/held"
        for lock in (self.before, self.after):
            lock["packages"][old_path]["resolved"] = "https://registry.npmjs.org/held/-/held-1.0.0.tgz"
        self.after["packages"][new_path] = self.after["packages"].pop(old_path)
        return old_path, new_path

    def test_unique_relocation_preserves_held_artifact_and_edges(self):
        old_path, _ = self.prepare_held_relocation()
        self.assertEqual(self.check()["status"], "RESOLUTION_PASSED")
        self.assertEqual(self.check(pins=frozenset({old_path}))["code"], "IMMUTABLE_LOCK_INSTANCE_CHANGED")

    def test_relocation_cannot_rebind_a_held_consumer_edge(self):
        _, _ = self.prepare_held_relocation()
        self.after["packages"]["app/node_modules/unrelated"] = {"version": "1.1.0"}
        self.assertEqual(self.check()["code"], "LOCK_UNRELATED_NODE_DELTA")

    def test_identical_held_copies_cannot_be_merged(self):
        old_path, new_path = self.prepare_held_relocation()
        self.before["packages"][new_path] = deepcopy(self.before["packages"][old_path])
        self.assertEqual(self.check()["code"], "LOCK_UNRELATED_NODE_DELTA")

    def test_held_copy_can_move_when_selected_version_reuses_its_old_slot(self):
        old_path = "node_modules/target"
        new_path = "app/node_modules/target"
        for lock in (self.before, self.after):
            lock["packages"]["app"]["dependencies"]["target"] = "1.0.0"
        self.assignment[("app", "dependencies", "target")] = "1.0.0"
        original = self.before["packages"][old_path]
        original.update(resolved="https://registry.npmjs.org/target/-/target-1.0.0.tgz",
                        integrity="sha512-original")
        original.pop("dependencies")
        self.after["packages"][new_path] = deepcopy(original)
        self.assertEqual(self.check()["status"], "RESOLUTION_PASSED")

        for lock in (self.before, self.after):
            lock["packages"]["ui"] = {"peerDependencies": {"target": "^1 || ^2"}}
        self.assertEqual(self.check()["code"], "HELD_LOCK_PROVIDER_CHANGED")
        self.assertEqual(self.check()["path"], "ui")

    def test_linked_workspace_preserves_only_unselected_child_edges(self):
        child_target = ("app", "dependencies", "target")
        root_link = (".", "dependencies", "app")
        for lock, version in ((self.before, "1.0.0"), (self.after, "2.0.0")):
            graph = lock["packages"]
            graph[""]["dependencies"]["app"] = "*"
            graph["app"]["version"] = "1.0.0"
            graph["app"]["dependencies"]["target"] = version
        deltas = {"": {"dependencies": {"target": "2.0.0"}},
                  "app": {"dependencies": {"target": "2.0.0"}}}
        assignment = {**self.assignment, child_target: "2.0.0", root_link: "1.0.0"}
        selected = {self.target, child_target}
        result = check_workspace_lock_delta(self.before, self.after, deltas, assignment, selected, None)
        self.assertEqual(result["status"], "RESOLUTION_PASSED", result)

        for lock in (self.before, self.after):
            lock["packages"]["app"]["peerDependencies"] = {"related": "^1 || ^2"}
        result = check_workspace_lock_delta(self.before, self.after, deltas, assignment, selected, None)
        self.assertEqual(result["code"], "HELD_LOCK_PROVIDER_CHANGED", result)
        self.assertEqual((result["path"], result["dependency"], result["section"]), ("app", "related", "peerDependencies"))

    def test_unrelated_churn_reports_held_peer_conflict_in_same_receipt(self):
        for lock in (self.before, self.after):
            lock["packages"]["node_modules/held"]["peerDependencies"] = {"target": "^1 || ^2"}
        self.after["packages"]["node_modules/unrelated"]["devOptional"] = True

        result = self.check()

        self.assertEqual(result["code"], "LOCK_UNRELATED_NODE_DELTA")
        self.assertEqual(result["path"], "node_modules/unrelated")
        self.assertEqual(result["heldConflict"], {
            "status": "RESOLUTION_FAILED", "code": "HELD_LOCK_PROVIDER_CHANGED",
            "path": "node_modules/held", "dependency": "target", "section": "peerDependencies",
        })

    def test_all_independent_held_conflicts_are_reported_in_one_receipt(self):
        for lock in (self.before, self.after):
            packages = lock["packages"]
            packages["node_modules/held"]["peerDependencies"] = {"target": "^1 || ^2"}
            packages["node_modules/unrelated"]["dependencies"] = {"related": "^1 || ^2"}

        result = self.check()
        self.assertEqual(result["code"], "HELD_LOCK_PROVIDER_CHANGED")
        self.assertEqual(result["heldConflictCount"], 2)
        self.assertEqual([(row["path"], row["dependency"]) for row in result["heldConflicts"]],
                         [("node_modules/held", "target"), ("node_modules/unrelated", "related")])

    def test_workspace_link_and_unapproved_manifest_edit_are_rejected(self):
        self.after["packages"]["node_modules/app"]["resolved"] = "unrelated"
        self.assertEqual(self.check()["code"], "LOCK_WORKSPACE_LINK_CHANGED")
        self.after["packages"]["app"]["dependencies"]["held"] = "^1"
        self.assertEqual(self.check()["code"], "LOCK_OWNER_RECORD_CHANGED")
