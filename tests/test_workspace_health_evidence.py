"""Tests for the Core-owned registry evidence path and privacy boundary."""
import unittest
from unittest.mock import MagicMock, Mock, call, patch

from dependency_live_roadmap_generator import DeadlineClock, LiveDataClient, RegistryInfrastructureError, VulnerabilityEvidenceUnavailable
from registry_advisory_evidence import RegistryAdvisory, RegistryAdvisoryEvidence
from workspace_health_evidence import collect_workspace_health_facts
from workspace_health_policy import WorkspaceHealthPolicy
from workspace_peer_model import declaration_id, plan_workspace_from_registry, prepare_workspace_from_registry


REGISTRY = "https://registry.example.invalid"
APP = ("packages/app", "dependencies", "demo")
LEGACY = ("packages/legacy", "dependencies", "demo")
HELD = (".", "dependencies", "held")


def packument(name):
    return {"name": name, "dist-tags": {"latest": "2.0.0"},
            "time": {"1.0.0": "2025-01-01T00:00:00Z", "2.0.0": "2026-05-01T00:00:00Z"},
            "versions": {v: {"name": name, "version": v,
                             "dist": {"tarball": f"{REGISTRY}/{name}/-/{name}-{v}.tgz"}}
                         for v in ("1.0.0", "2.0.0")}}


class WorkspaceRegistryHealthTests(unittest.TestCase):
    def setUp(self):
        self.client = LiveDataClient(REGISTRY, timeout=1, batch_size=10, sleep_sec=0)
        self.client.draft = True
        self.client.set_deadline(DeadlineClock(20))
        self.client.fetch_npm_metadata = Mock(side_effect=packument)
        self.client.query_osv_versions = Mock(side_effect=lambda _, versions: {v: [] for v in versions})
        self.packages = {
            "packages/app/node_modules/demo": {"version": "1.0.0"},
            "packages/legacy/node_modules/demo": {"version": "2.0.0"},
            "node_modules/held": {"version": "2.0.0"},
        }
        self.declarations = {APP: "1.0.0", LEGACY: "2.0.0", HELD: "2.0.0"}

    def plan(self, allowed=frozenset({"demo", "held"}), **kwargs):
        return plan_workspace_from_registry(
            self.packages, self.declarations, {APP: (1, 2)}, {}, self.client,
            candidate_versions={APP: ("1.0.0", "2.0.0")},
            health_policy=WorkspaceHealthPolicy("yellow", 80), osv_allowed_names=allowed, **kwargs,
        )

    def test_registry_path_deduplicates_exact_osv_and_keeps_held_declarations(self):
        result = self.plan()
        self.assertEqual(result["assignment"][declaration_id(APP)], "2.0.0")
        self.assertEqual(result["assignment"][declaration_id(LEGACY)], "2.0.0")
        self.assertEqual(result["policy"]["lagDenominator"], 3)
        self.assertEqual(result["policy"]["evidence"]["exactVersionCount"], 3)
        self.assertEqual(result["policy"]["evidence"]["unknownSecurityVersionCount"], 0)
        self.assertCountEqual(self.client.fetch_npm_metadata.call_args_list, [call("demo"), call("held")])
        self.assertEqual(self.client.query_osv_versions.call_args_list,
                         [call("demo", ["1.0.0", "2.0.0"]), call("held", ["2.0.0"])])

    def test_prepared_model_reuses_one_evidence_snapshot_for_distinct_assignments(self):
        with patch("workspace_peer_model.solve_z3_exact", side_effect=AssertionError("preparation must not solve")):
            prepared = prepare_workspace_from_registry(
                self.packages, self.declarations, {APP: (1, 2)}, {}, self.client,
                candidate_versions={APP: ("1.0.0", "2.0.0")},
                health_policy=WorkspaceHealthPolicy("yellow", 0), osv_allowed_names=frozenset({"demo", "held"}),
            )
        metadata_count = self.client.fetch_npm_metadata.call_count
        advisory_count = self.client.query_osv_versions.call_count
        self.client.fetch_npm_metadata.side_effect = AssertionError("late metadata request")
        self.client.query_osv_versions.side_effect = AssertionError("late advisory request")
        first = prepared.solve(timeout_ms=1000)
        second = prepared.solve((first["assignment"],), timeout_ms=1000)
        self.assertEqual(first["status"], "SAT_IN_MODELED_DOMAIN")
        self.assertEqual(second["status"], "SAT_IN_MODELED_DOMAIN")
        self.assertNotEqual(first["assignment"], second["assignment"])
        self.assertEqual(first["modelDigest"], second["modelDigest"])
        self.assertEqual(first["policy"]["evidence"], second["policy"]["evidence"])
        self.assertEqual(self.client.fetch_npm_metadata.call_count, metadata_count)
        self.assertEqual(self.client.query_osv_versions.call_count, advisory_count)
        first["domain"]["candidateCount"] = -1
        first["policy"]["evidence"]["snapshotSha256"] = "corrupted by caller"
        repeated = prepared.solve(timeout_ms=1000)
        self.assertGreater(repeated["domain"]["candidateCount"], 0)
        self.assertEqual(repeated["policy"]["evidence"], second["policy"]["evidence"])
        self.assertEqual(repeated["assignment"], first["assignment"])

    def test_unapproved_osv_name_remains_unknown_and_is_not_sent(self):
        result = self.plan(frozenset({"demo"}))
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["assignment"])
        self.assertEqual(result["policy"]["evidence"]["osvSkippedNameCount"], 1)
        self.assertEqual(result["policy"]["evidence"]["unknownSecurityVersionCount"], 1)
        self.client.query_osv_versions.assert_called_once_with("demo", ["1.0.0", "2.0.0"])

    def test_osv_outage_and_missing_date_are_not_clean_or_stale(self):
        meta = packument("demo")
        del meta["time"]["1.0.0"]
        self.client.query_osv_versions.side_effect = VulnerabilityEvidenceUnavailable("unavailable")
        facts, evidence = collect_workspace_health_facts(
            self.client, {"demo": meta}, {"demo": ("1.0.0", "2.0.0")},
            lag_months=12, osv_allowed_names=frozenset({"demo"}),
        )
        self.assertIsNone(facts["demo", "1.0.0"].lag_ok)
        self.assertTrue(facts["demo", "2.0.0"].lag_ok)
        self.assertIsNone(facts["demo", "2.0.0"].severities)
        self.assertEqual((evidence["unknownLagVersionCount"], evidence["unknownSecurityVersionCount"]), (1, 2))

    def test_registry_only_batches_exact_pairs_across_owners_and_keeps_final_audit_open(self):
        self.client.allow_registry_metadata_redirects = False
        response_hash = "a" * 64
        advisory = RegistryAdvisory("synthetic", "high", "<2.0.0")
        pairs = {("demo", "1.0.0"): RegistryAdvisoryEvidence("AFFECTED", "EXACT", (advisory,), response_hash),
                 ("demo", "2.0.0"): RegistryAdvisoryEvidence("NO_REPORTED_ADVISORIES", "EXACT", response_sha256=response_hash),
                 ("held", "2.0.0"): RegistryAdvisoryEvidence("NO_REPORTED_ADVISORIES", "EXACT", response_sha256=response_hash)}
        with patch.object(self.client, "query_registry_advisory_evidence", return_value=pairs) as query:
            result = self.plan(registry_advisory_source=REGISTRY)
        query.assert_called_once_with(list(pairs), REGISTRY, max_match_evaluations=256)
        self.client.query_osv_versions.assert_not_called()
        self.assertEqual(result["assignment"][declaration_id(APP)], "2.0.0")
        self.assertEqual(result["assignment"][declaration_id(LEGACY)], "2.0.0")
        self.assertEqual(result["policy"]["lagDenominator"], 3)
        self.assertEqual(result["policy"]["finalAudit"], "NOT_RUN")
        self.assertEqual(result["policy"]["evidence"]["source"], "REGISTRY_BULK_ADVISORY")
        self.assertEqual(result["policy"]["evidence"]["registryAdvisoryResponseSha256"], [response_hash])

    def test_registry_only_pair_budget_stays_unknown_without_osv_fallback(self):
        self.client.allow_registry_metadata_redirects = False
        with patch("workspace_health_evidence._MAX_REGISTRY_ADVISORY_PAIRS", 2), patch.object(
            self.client, "query_registry_advisory_evidence",
        ) as query:
            result = self.plan(registry_advisory_source=REGISTRY)
        query.assert_not_called()
        self.client.query_osv_versions.assert_not_called()
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["policy"]["evidence"]["registryAdvisoryUnknownReasons"], {"PAIR_BUDGET_EXHAUSTED": 3})

    def test_registry_only_rejects_mismatch_before_fetching_private_names(self):
        self.client.allow_registry_metadata_redirects = False
        with self.assertRaisesRegex(ValueError, "WORKSPACE_REGISTRY_ADVISORY_NOT_AUTHORIZED"):
            self.plan(registry_advisory_source=REGISTRY + "/other")
        self.client.fetch_npm_metadata.assert_not_called()

    def test_strict_metadata_request_refuses_redirect(self):
        client = LiveDataClient(REGISTRY, timeout=1, batch_size=10, sleep_sec=0,
                                allow_registry_metadata_redirects=False)
        response = MagicMock(status_code=302)
        with patch.object(client.session, "get", return_value=response) as get:
            with self.assertRaisesRegex(RegistryInfrastructureError, "metadata redirect refused"):
                client.fetch_npm_metadata("demo")
        self.assertEqual(get.call_count, 1)
        self.assertIs(get.call_args.kwargs["allow_redirects"], False)
        response.close.assert_called_once()

    def test_no_policy_network_without_a_deadline(self):
        self.client.set_deadline(None)
        with self.assertRaisesRegex(ValueError, "WORKSPACE_POLICY_REGISTRY_DEADLINE_REQUIRED"):
            self.plan()
        self.client.fetch_npm_metadata.assert_not_called()
