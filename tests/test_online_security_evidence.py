"""Online OSV must not turn incomplete evidence into a security target.

The planner regression uses real loopback HTTP responses, without querying a
public registry/OSV service or installing a package. Vector fixtures use the
CVSS notation defined by FIRST and the OSV severity contract.
"""
from __future__ import annotations

import copy
import http.server
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import dependency_live_roadmap_generator as core


CRITICAL_V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LOW_V3 = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
CRITICAL_V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"


class OnlineSecurityEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name)
        (self.project / "package.json").write_text(json.dumps({
            "name": "fixture", "dependencies": {"demo": "1.0.0"},
        }), encoding="utf-8")
        self.visits = []
        self.batch_override = None
        self.details = {
            "TEST-CURRENT": {"id": "TEST-CURRENT", "database_specific": {"severity": "critical"}},
            "TEST-TARGET": {"id": "TEST-TARGET"},
        }
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def reply(self, value):
                raw = json.dumps(value).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                owner.visits.append(("GET", self.path))
                if self.path == "/demo":
                    versions = ("1.0.0", "2.0.0", "3.0.0")
                    self.reply({
                        "name": "demo", "dist-tags": {"latest": "3.0.0"},
                        "versions": {version: {
                            "name": "demo", "version": version,
                            "dist": {"tarball": f"{owner.registry}/demo/-/demo-{version}.tgz"},
                        } for version in versions},
                        "time": {version: "2026-11-01T00:00:00Z" for version in versions},
                    })
                elif self.path.startswith("/osv/"):
                    self.reply(owner.details[self.path.removeprefix("/osv/")])
                else:
                    self.send_error(404)

            def do_POST(self):
                owner.visits.append(("POST", self.path))
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if owner.batch_override is not None:
                    self.reply(owner.batch_override)
                    return
                ids = {"1.0.0": "TEST-CURRENT", "2.0.0": "TEST-TARGET"}
                self.reply({"results": [
                    {"vulns": [{"id": ids[query["version"]]}]} if query["version"] in ids else {}
                    for query in payload["queries"]
                ]})

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.registry = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        for context in (
            patch.dict(os.environ, {
                "DEPLOOM_DRAFT_OSV_DIR": "", "DEPLOOM_DRAFT_DISABLE_EXTERNAL_EVIDENCE": "0",
                "DEPLOOM_DRAFT_PRIVATE_SCOPES": "",
            }),
            patch.object(core, "OSV_QUERY_BATCH", self.registry + "/querybatch"),
            patch.object(core, "OSV_VULN", self.registry + "/osv/{id}"),
        ):
            context.start()
            self.addCleanup(context.stop)
        self.client = core.LiveDataClient(self.registry, timeout=2, batch_size=16, sleep_sec=0)
        self.client.draft = True
        self.client.progress = lambda **_kwargs: None
        self.addCleanup(self.client.session.close)

    def _stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def plan(self):
        rows = core.analyze_project(
            core.ProjectSpec("fixture", self.project), self.client, {}, False, 0,
            tolerate_registry_failure=True,
        )
        self.assertEqual(1, len(rows))
        return rows[0]

    def test_unrated_target_cannot_satisfy_no_critical_or_no_high(self):
        row = self.plan()
        self.assertEqual("U:1", row.vuln_evidence_by_version["2.0.0"])
        self.assertEqual("3.0.0", row.min_no_critical)
        self.assertEqual("3.0.0", row.min_no_high)
        self.assertEqual("3.0.0", row.target_default)
        self.assertEqual("3.0.0", row.target_green)
        self.assertFalse(core._projected_row_security_full(row, "2.0.0")[-1])
        self.assertFalse(core._candidate_satisfies_fast_policy(
            [row], {"demo": "2.0.0"}, {"demo": "1.0.0"}, {"demo"}, "fixture",
        ))

    def test_cvss_only_critical_target_is_not_selected_as_safe(self):
        self.details["TEST-TARGET"]["severity"] = [{"type": "CVSS_V3", "score": CRITICAL_V3}]
        row = self.plan()
        self.assertEqual("C:1", row.vuln_evidence_by_version["2.0.0"])
        self.assertEqual("3.0.0", row.min_no_high)
        self.assertEqual("3.0.0", row.target_default)

    def test_explicit_low_and_clean_controls_remain_distinct(self):
        self.details["TEST-TARGET"]["database_specific"] = {"severity": "low"}
        row = self.plan()
        self.assertEqual("2.0.0", row.min_no_critical)
        self.assertEqual("2.0.0", row.min_no_high)
        self.assertEqual("3.0.0", row.min_no_vuln)
        self.assertEqual("2.0.0", row.target_default)
        self.assertEqual((0, 0, 0, 1, True), core._projected_row_security_full(row, "2.0.0"))
        self.assertTrue(core._candidate_satisfies_fast_policy(
            [row], {"demo": "2.0.0"}, {"demo": "1.0.0"}, {"demo"}, "fixture",
        ))

    def test_partially_rated_target_cannot_pass_projection_or_fast_goal(self):
        self.details["TEST-TARGET"].update(
            database_specific={"severity": "low"},
            severity=[{"type": "FUTURE_SCORE", "score": "1"}],
        )
        row = self.plan()
        self.assertEqual("3.0.0", row.min_no_high)
        self.assertEqual((0, 0, 0, 1, False), core._projected_row_security_full(row, "2.0.0"))
        self.assertFalse(core._candidate_satisfies_fast_policy(
            [row], {"demo": "2.0.0"}, {"demo": "1.0.0"}, {"demo"}, "fixture",
        ))
        self.assertEqual("L:1, U:1", row.vuln_evidence_by_version["2.0.0"])
        # Another planner objective can choose this exact version independently
        # of min_no_high. Its final plan must still retain the incomplete rating.
        row.target_default = row.target_yellow = row.target_green = "2.0.0"
        plan = core.build_draft_plan({"fixture": [row]}, {}, {
            "fixture": core.compute_project_health([row], "fixture", None),
        })
        health = plan["proposals"][0]["health"]
        self.assertEqual("unknown", health["postPlanGoal"])
        self.assertEqual(1, health["postPlanSecurityUnknown"])
        self.assertEqual(1, health["postPlanLow"])

    def test_partial_critical_rating_keeps_positive_finding_and_unknown(self):
        self.details["TEST-TARGET"].update(
            database_specific={"severity": "critical"},
            severity=[{"type": "CVSS_V3", "score": "not-a-vector"}],
        )
        row = self.plan()
        self.assertEqual((1, 0, 0, 0, False), core._projected_row_security_full(row, "2.0.0"))
        self.assertEqual("C:1, U:1", row.vuln_evidence_by_version["2.0.0"])

    def test_final_enrichment_preserves_package_context_and_incomplete_rating(self):
        row = self.plan()
        row.target_default = row.target_yellow = row.target_green = "2.0.0"
        for advisory, summary, expected in (
            ({"id": "PACKAGE-SPECIFIC", "affected": [
                {"package": {"ecosystem": "npm", "name": name},
                 "severity": [{"type": "CVSS_V3", "score": score}]}
                for name, score in (("demo", CRITICAL_V3), ("other", LOW_V3))
            ]}, "C:1", (1, 0, 0, 0, True)),
            ({"id": "INCOMPLETE", "database_specific": {"severity": "low"},
              "severity": [{"type": "FUTURE_SCORE", "score": "1"}]},
             "L:1, U:1", (0, 0, 0, 1, False)),
        ):
            with self.subTest(advisory=advisory):
                row.vuln_evidence_by_version.pop("2.0.0", None)
                with patch.object(self.client, "_query_registry_security_pairs", return_value={
                    ("demo", "2.0.0"): [advisory],
                }):
                    core.enrich_final_registry_security({"fixture": [row]}, self.client, self.registry)
                self.assertEqual(summary, row.vuln_evidence_by_version["2.0.0"])
                self.assertEqual(expected, core._projected_row_security_full(row, "2.0.0"))

    def test_final_current_enrichment_does_not_clear_unknown_for_partial_rating(self):
        row = self.plan()
        row.target_default = row.target_yellow = row.target_green = core.NO_ACTION
        for advisory, summary, unknown in (
            ({"id": "INCOMPLETE", "database_specific": {"severity": "low"},
              "severity": [{"type": "CVSS_V3", "score": "not-a-vector"}]}, "L:1, U:1", True),
            ({"id": "COMPLETE", "database_specific": {"severity": "low"}}, "L:1", False),
        ):
            with self.subTest(advisory=advisory):
                row.current_vulns = "unknown"
                row.draft_unknown = "osv-unavailable"
                row.current_security_evidence = {"status": "UNKNOWN", "reason": "PRIOR_UNAVAILABLE"}
                with patch.object(self.client, "_query_registry_security_pairs", return_value={
                    ("demo", "1.0.0"): [advisory],
                }):
                    core.enrich_final_registry_security({"fixture": [row]}, self.client, self.registry)
                self.assertEqual(summary, row.current_vulns)
                self.assertEqual("osv-unavailable" if unknown else "", row.draft_unknown)
                self.assertEqual("UNKNOWN" if unknown else "ASSESSED", row.current_security_evidence["status"])
                self.assertEqual(not unknown, core._projected_row_security_full(row, core.NO_ACTION)[-1])

    def test_final_enrichment_does_not_erase_existing_unrated_finding_with_registry_zero(self):
        self.details["TEST-CURRENT"] = {"id": "TEST-CURRENT"}
        row = self.plan()
        for target, version in (("2.0.0", "2.0.0"), (core.NO_ACTION, "1.0.0")):
            with self.subTest(target=target):
                row.target_default = row.target_yellow = row.target_green = target
                with patch.object(self.client, "_query_registry_security_pairs", return_value={
                    ("demo", version): [],
                }) as registry:
                    core.enrich_final_registry_security({"fixture": [row]}, self.client, self.registry)
                registry.assert_not_called()
                self.assertFalse(core._projected_row_security_full(row, target)[-1])

    def test_malformed_batch_cannot_publish_clean_or_partial_cache(self):
        payloads = (
            {"results": [{"vulns": [{}]}]},
            {"results": [{"vulns": [{"id": ""}]}]},
            {"results": [{"vulns": [{"id": "../outside"}]}]},
            {"results": [{"vulns": None}]},
            {"results": [{"vulns": {}}]},
            {"results": [{}, {}]},
            {"results": []},
            {"results": {}},
            {"results": [{"error": "upstream failure"}]},
            {"results": [{}], "error": "partial response"},
            {"results": [{"next_page_token": "more findings"}]},
            {"results": [{"next_page_token": None}]},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                self.client.osv_cache.clear()
                self.client.vuln_detail_cache.clear()
                self.batch_override = payload
                with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                    self.client.query_osv_versions("demo", ["3.0.0"])
                self.assertEqual({}, self.client.osv_cache)
                self.assertEqual({}, self.client.vuln_detail_cache)
        self.batch_override = {"results": [{}, {"vulns": [{}]}]}
        with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
            self.client.query_osv_versions("demo", ["3.0.0", "2.0.0"])
        self.assertEqual({}, self.client.osv_cache)

    def test_malformed_or_mismatched_detail_does_not_enter_cache(self):
        details = (
            {}, {"id": "OTHER"}, {"id": "TEST-TARGET", "severity": {}},
            {"id": "TEST-TARGET", "severity": [{}]},
            {"id": "TEST-TARGET", "severity": [{"type": "CVSS_V3", "score": 9.8}]},
            {"id": "TEST-TARGET", "database_specific": []},
            {"id": "TEST-TARGET", "error": "upstream failure"},
            {"id": "TEST-TARGET", "affected": [{"severity": {}}]},
        )
        for detail in details:
            with self.subTest(detail=detail):
                self.client.osv_cache.clear()
                self.client.vuln_detail_cache.clear()
                self.details["TEST-TARGET"] = copy.deepcopy(detail)
                with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                    self.client.query_osv_versions("demo", ["2.0.0"])
                self.assertEqual({}, self.client.osv_cache)
                self.assertEqual({}, self.client.vuln_detail_cache)

    def test_old_invalid_detail_cache_is_revalidated_before_reuse(self):
        self.client.vuln_detail_cache["TEST-TARGET"] = {"id": "OTHER"}
        result = self.client.query_osv_versions("demo", ["2.0.0"])
        self.assertEqual("TEST-TARGET", result["2.0.0"][0]["id"])
        self.assertIn(("GET", "/osv/TEST-TARGET"), self.visits)

    def test_old_malformed_pair_cache_is_not_reused_as_clean(self):
        self.client.osv_cache["demo", "2.0.0"] = [{}]
        result = self.client.query_osv_versions("demo", ["2.0.0"])
        self.assertEqual("TEST-TARGET", result["2.0.0"][0]["id"])
        self.assertIn(("POST", "/querybatch"), self.visits)

    def test_unrated_current_retains_finding_and_explicit_unknown_diagnostic(self):
        self.details["TEST-CURRENT"] = {"id": "TEST-CURRENT"}
        row = self.plan()
        self.assertEqual("U:1", row.current_vulns)
        self.assertEqual("UNKNOWN", row.current_security_evidence["status"])
        self.assertEqual("MISSING_SEVERITY", row.current_security_evidence["reason"])
        self.assertEqual("osv-unavailable", row.draft_unknown)

    def test_package_specific_cvss_uses_the_queried_package(self):
        self.details["TEST-TARGET"]["affected"] = [
            {"package": {"ecosystem": "npm", "name": name},
             "severity": [{"type": "CVSS_V3", "score": score}]}
            for name, score in (("demo", CRITICAL_V3), ("other", LOW_V3))
        ]
        row = self.plan()
        self.assertEqual("C:1", row.vuln_evidence_by_version["2.0.0"])
        self.assertEqual("3.0.0", row.min_no_high)
        result = self.client.query_osv_versions("demo", ["2.0.0", "3.0.0"])
        self.assertEqual("2.0.0", core.min_by_vuln(["2.0.0", "3.0.0"], result, "no-high", package="other"))
        self.assertEqual("3.0.0", core.min_by_vuln(["2.0.0", "3.0.0"], result, "no-high"))


class SeverityContractTests(unittest.TestCase):
    def test_cvss_base_vectors_use_their_defined_scoring_system(self):
        for kind, vector, rank in (
            ("CVSS_V2", "AV:N/AC:L/Au:N/C:C/I:C/A:C", 4),
            ("CVSS_V3", CRITICAL_V3, 4),
            ("CVSS_V3", CRITICAL_V3.replace("3.1", "3.0"), 4),
            ("CVSS_V3", LOW_V3, 1),
            ("CVSS_V4", CRITICAL_V4, 4),
            ("CVSS_V4", CRITICAL_V4 + "/E:U/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N", 4),
        ):
            with self.subTest(kind=kind, vector=vector):
                self.assertEqual(rank, core.severity_rank({"id": "TEST", "severity": [{"type": kind, "score": vector}]}))

    def test_unknown_invalid_or_numeric_severity_never_proves_a_security_target(self):
        for severity in (
            [], [{"type": "CVSS_V3", "score": "9.8"}],
            [{"type": "CVSS_V3", "score": CRITICAL_V4}],
            [{"type": "CVSS_V3", "score": CRITICAL_V3 + "/AV:L"}],
            [{"type": "CVSS_V3", "score": CRITICAL_V3.replace("/AV:N", "")}],
            [{"type": "FUTURE_SCORE", "score": "1"}],
        ):
            with self.subTest(severity=severity):
                evidence = {"1.0.0": [{"id": "TEST", "severity": severity}], "2.0.0": []}
                for mode in ("no-critical", "no-high", "no-vuln"):
                    self.assertEqual("2.0.0", core.min_by_vuln(["1.0.0", "2.0.0"], evidence, mode))

    def test_multiple_ratings_keep_the_worst_and_unknown_is_not_a_low_rating(self):
        low = {"type": "CVSS_V3", "score": LOW_V3}
        critical = {"type": "CVSS_V3", "score": CRITICAL_V3}
        for ratings in ([low, critical], [critical, low]):
            self.assertEqual(4, core.severity_rank({"id": "TEST", "database_specific": {"severity": "low"}, "severity": ratings}))
        for record in (
            {"id": "TEST", "database_specific": {"severity": "FUTURE_CATEGORY"}, "severity": [low]},
            {"id": "TEST", "database_specific": {"severity": "low"}, "severity": [{"type": "FUTURE_SCORE", "score": "1"}]},
        ):
            self.assertEqual("2.0.0", core.min_by_vuln(["1.0.0", "2.0.0"], {"1.0.0": [record], "2.0.0": []}, "no-high"))


if __name__ == "__main__":
    unittest.main()
