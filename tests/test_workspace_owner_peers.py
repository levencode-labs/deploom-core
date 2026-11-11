import copy
import unittest

from workspace_peer_model import (WorkspaceCandidate, WorkspaceDomain, WorkspaceTopology,
                                  declaration_id, plan_workspace_from_lock, plan_workspace_upgrade)


class WorkspaceOwnerPeerTests(unittest.TestCase):
    def setUp(self):
        self.key = (".", "dependencies", "provider")
        self.domains = {self.key: WorkspaceDomain("1.0.0", tuple(
            WorkspaceCandidate(v, {}) for v in ("2.3.0", "2.2.0")), mutable=True)}
        self.packages = {"": {}, "packages/keeper": {"version": "1.0.0", "peerDependencies": {
            "provider": "^1 || >=2 <2.3"}},
            "node_modules/keeper": {"link": True, "resolved": "packages/keeper"},
            "node_modules/provider": {"version": "1.0.0"}}

    def plan(self, **kwargs):
        return plan_workspace_from_lock(self.packages, self.domains, include_constraint_evidence=True, **kwargs)

    def test_held_owner_limits_mutable_provider_without_extra_install_variable(self):
        result = self.plan()
        self.assertEqual(result["status"], "SAT_IN_MODELED_DOMAIN")
        self.assertEqual(result["assignment"], {declaration_id(self.key): "2.2.0"})
        self.assertEqual(result["ownerPeerConstraintCount"], 1)
        self.assertIn("workspace-owner-peer", str(result))

    def test_root_owner_and_exact_incompatible_pin(self):
        self.packages[""] = self.packages.pop("packages/keeper")
        self.domains[self.key] = WorkspaceDomain("1.0.0", self.domains[self.key].candidates,
                                                mutable=True, exact_target="2.3.0")
        self.assertEqual(self.plan()["status"], "UNSAT_IN_MODELED_DOMAIN")

    def test_optional_proven_absence_is_allowed_but_malformed_slot_is_unknown(self):
        owner = self.packages["packages/keeper"]
        owner["peerDependencies"] = {"absent": "^2"}
        owner["peerDependenciesMeta"] = {"absent": {"optional": True}}
        self.assertEqual(self.plan()["status"], "SAT_IN_MODELED_DOMAIN")
        self.packages["node_modules/absent"] = {}
        self.assertEqual(self.plan()["status"], "UNKNOWN")

    def test_malformed_nearest_slot_cannot_fall_back_to_compatible_ancestor(self):
        for optional in (False, True):
            self.packages["packages/keeper"]["peerDependenciesMeta"] = {"provider": {"optional": optional}}
            for malformed in ({}, None, {"version": ""}):
                with self.subTest(optional=optional, malformed=malformed):
                    self.packages["packages/keeper/node_modules/provider"] = malformed
                    result = self.plan()
                    self.assertEqual(result["status"], "UNKNOWN")
                    self.assertIsNone(result["assignment"])
                    self.assertIn("OWNER_PEER_PROVIDER_UNPROVEN", result["reason"])

    def test_invalid_fixed_provider_version_is_unknown(self):
        self.packages["packages/keeper/node_modules/provider"] = {"version": "bad",
            "resolved": "https://registry.example/provider.tgz", "integrity": "sha512-fixture"}
        result = self.plan()
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["assignment"])
        self.assertIn("OWNER_PEER_PROVIDER_UNPROVEN", result["reason"])

    def test_required_missing_peer_and_unlinked_owner_are_unknown(self):
        self.packages["packages/keeper"]["peerDependencies"] = {"absent": "^2"}
        self.assertEqual(self.plan()["status"], "UNKNOWN")
        del self.packages["node_modules/keeper"]
        self.assertIn("OWNER_LINK_UNPROVEN", self.plan()["reason"])

    def test_nested_provider_is_bound_by_actual_owner_slot(self):
        self.packages["packages/keeper/node_modules/provider"] = {"version": "2.2.0",
            "resolved": "https://registry.example/provider.tgz", "integrity": "sha512-fixture"}
        self.assertEqual(self.plan()["assignment"][declaration_id(self.key)], "2.3.0")
        self.packages["packages/keeper/node_modules/provider"]["version"] = "2.3.0"
        self.assertEqual(self.plan()["status"], "UNSAT_IN_MODELED_DOMAIN")

    def test_unsupported_peer_range_is_unknown_not_unsat(self):
        self.packages["packages/keeper"]["peerDependencies"]["provider"] = "workspace:*"
        self.assertIn("OWNER_PEER_RANGE_UNSUPPORTED", self.plan()["reason"])

    def test_optional_present_peer_must_satisfy_range(self):
        self.packages["packages/keeper"]["peerDependenciesMeta"] = {"provider": {"optional": True}}
        self.assertEqual(self.plan()["assignment"][declaration_id(self.key)], "2.2.0")

    def test_effective_owner_override_uses_matching_observed_identity(self):
        result = self.plan(effective_peer_ranges={
            ("packages/keeper", "1.0.0", "provider", "^1 || >=2 <2.3"): "2.3.0"})
        self.assertEqual(result["assignment"][declaration_id(self.key)], "2.3.0")

    def test_shadowing_installed_dependency_follows_native_preflight(self):
        self.packages["packages/keeper"]["dependencies"] = {"provider": "^2"}
        self.assertEqual(self.plan()["ownerPeerConstraintCount"], 0)

    def test_proposed_topology_does_not_silently_drop_owner_contract(self):
        result = plan_workspace_upgrade(self.packages, {self.key: "1.0.0"},
            {self.key: ("2.2.0",)}, {}, {}, topology=WorkspaceTopology({}, ((self.key,),)))
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["reason"], "PROPOSED_LAYOUT_OWNER_PEERS_UNPROVEN")


if __name__ == "__main__":
    unittest.main()
