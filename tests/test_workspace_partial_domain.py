"""Partial candidate evidence must preserve witnesses without inventing UNSAT."""
import unittest
from dataclasses import replace

from workspace_peer_model import (
    WorkspaceCandidate, WorkspaceDomain, declaration_id,
    plan_workspace_from_lock, plan_workspace_in_topology, plan_workspace_upgrade, plan_workspace_from_registry,
)


class PartialDomainTests(unittest.TestCase):
    key = (".", "dependencies", "plugin")
    provider = (".", "dependencies", "engine")

    def setUp(self):
        self.packages = {"node_modules/plugin": {"version": "1.0.0"}}
        self.known = WorkspaceCandidate("1.0.0", {})
        self.unknown = WorkspaceCandidate("2.0.0", {"new-peer": "^1"}, frozenset({"new-peer"}))
        self.domain = WorkspaceDomain("1.0.0", (self.unknown, self.known), mutable=True)

    def test_unknown_optional_alternative_does_not_poison_existing_witness(self):
        result = plan_workspace_from_lock(self.packages, {self.key: self.domain})
        self.assertEqual(result["status"], "SAT_IN_MODELED_DOMAIN")
        self.assertEqual(result["assignment"], {declaration_id(self.key): "1.0.0"})
        self.assertEqual(result["domain"]["evidenceCoverage"], "PARTIAL")
        self.assertEqual(result["domain"]["candidateCount"], 2)
        self.assertEqual(result["domain"]["unprovenCandidates"][0]["version"], "2.0.0")
        self.assertEqual(result["optimality"], "PROVEN_IN_EVIDENCED_SUBDOMAIN")
        self.assertEqual(result["verification"], "NOT_VERIFIED")

    def test_exact_unknown_is_not_replaced_by_known_current(self):
        result = plan_workspace_from_lock(self.packages, {self.key: replace(self.domain, exact_target="2.0.0")})
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["assignment"])
        self.assertEqual(result["optimality"], "NOT_PROVEN")

    def test_exhausted_proven_candidates_are_unknown_not_unsat(self):
        result = plan_workspace_from_lock(self.packages, {self.key: self.domain},
                                         excluded_assignments=({declaration_id(self.key): "1.0.0"},))
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["assignment"])

    def test_missing_metadata_is_local_but_held_metadata_is_required(self):
        metadata = {"plugin": {"versions": {"1.0.0": {"name": "plugin", "version": "1.0.0"}}}}
        result = plan_workspace_upgrade(self.packages, {self.key: "^1"},
                                        {self.key: ("2.0.0", "1.0.0")}, {}, metadata)
        self.assertEqual(result["status"], "SAT_IN_MODELED_DOMAIN")
        self.assertEqual(result["domain"]["unprovenCandidateCount"], 1)
        held = plan_workspace_upgrade(self.packages, {self.key: "^1"}, {}, {}, {})
        self.assertEqual(held["status"], "UNKNOWN")
        self.assertIsNone(held["assignment"])

    def test_unknown_provider_version_cannot_create_false_unsat(self):
        domains = {
            self.key: WorkspaceDomain("1.0.0", (WorkspaceCandidate("1.0.0", {"engine": "^2"}),)),
            self.provider: WorkspaceDomain("1.0.0", (
                WorkspaceCandidate("2.0.0", {}, evidence_reason="fixture missing metadata"), self.known,
            ), mutable=True),
        }
        result = plan_workspace_in_topology(domains, {(self.key, "engine"): self.provider},
                                            ((self.key,), (self.provider,)))
        self.assertEqual(result["status"], "UNKNOWN")

    def test_unknown_shared_mutable_slot_does_not_become_singleton(self):
        other = ("packages/app", "dependencies", "plugin")
        result = plan_workspace_from_lock(self.packages, {self.key: self.domain, other: self.domain})
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIn("SHARED_SLOT_RELAYOUT_UNMODELED", result["reason"])

    def test_optional_absence_and_incompatible_presence_remain_distinct(self):
        candidate = WorkspaceCandidate("1.0.0", {"engine": "^2"}, frozenset({"engine"}))
        domains = {self.key: WorkspaceDomain("1.0.0", (candidate,)),
                   self.provider: WorkspaceDomain("1.0.0", (self.known,))}
        groups = ((self.key,), (self.provider,))
        present = plan_workspace_in_topology(domains, {(self.key, "engine"): self.provider}, groups)
        self.assertEqual(present["status"], "UNSAT_IN_MODELED_DOMAIN")
        self.assertEqual(present["domain"]["evidenceCoverage"], "COMPLETE")
        absent = plan_workspace_in_topology(domains, {(self.key, "engine"): None}, groups)
        self.assertEqual(absent["status"], "SAT_IN_MODELED_DOMAIN")

    def test_unknown_engine_is_local_and_original_ranking_is_preserved(self):
        domain = WorkspaceDomain("1.0.0", (
            WorkspaceCandidate("4.0.0", {}, engines={"node": ">=24"}),
            WorkspaceCandidate("3.0.0", {}), WorkspaceCandidate("2.0.0", {}),
        ), mutable=True)
        result = plan_workspace_from_lock(self.packages, {self.key: domain})
        self.assertEqual(result["assignment"][declaration_id(self.key)], "3.0.0")

    def test_partial_health_unsat_is_not_an_authoritative_policy_block(self):
        def blocked(model, budget):
            return {"status": "UNSAT_IN_MODELED_DOMAIN", "assignment": None,
                    "policy": {"status": "BLOCKED_IN_MODELED_DOMAIN"}}
        result = plan_workspace_from_lock(self.packages, {self.key: self.domain}, health_solver=blocked)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["policy"]["status"], "UNKNOWN")

    def test_explicit_registry_alternatives_preserve_evidence_gaps(self):
        class Registry:
            def fetch_npm_metadata(_, name):
                return {"versions": {
                    "1.0.0": {"name": "plugin", "version": "1.0.0"},
                    "3.0.0": {"name": "plugin", "version": "3.0.0"},
                }}
            def registry_tarball_url(_, packument, version):
                return "unapproved"
            def registry_artifact_url_allowed(_, url):
                return False
        result = plan_workspace_from_registry(
            self.packages, {self.key: "^1"}, {self.key: (1, 2, 3)}, {}, Registry(),
            candidate_versions={self.key: ("3.0.0", "2.0.0", "1.0.0")},
        )
        self.assertEqual(result["status"], "SAT_IN_MODELED_DOMAIN")
        self.assertEqual(result["domain"]["candidateCount"], 3)
        self.assertEqual(result["domain"]["unprovenCandidateCount"], 2)
        self.assertEqual(len(result["modelDigest"]), 64)
        self.assertEqual(len(result["assignmentDigest"]), 64)
