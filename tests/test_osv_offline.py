import json
import os
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import osv_offline


class OfflineEvidenceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.digest = "a" * 64
        db = self.root / (self.digest + ".sqlite")
        with closing(sqlite3.connect(db)) as conn:
            conn.execute("CREATE TABLE advisory(name, id, severity, versions, ranges)")
            conn.execute("INSERT INTO advisory VALUES (?,?,?,?,?)",
                         ("example", "TEST-1", "HIGH", "[]", json.dumps([
                             ["SEMVER", [{"introduced": "0"}, {"fixed": "2.0.0"}]]])))
            conn.commit()
        self.now = int(time.time())
        self.manifest = dict(schema=1, ecosystem="npm", sha256=self.digest,
                             unpacked=db.stat().st_size, published=self.now)
        self.pointer = self.root / "active.json"
        self.pointer.write_text(json.dumps(self.manifest))

    def test_only_confirmed_versions_receive_evidence(self):
        evidence = osv_offline.query(self.root, "example", ["1.9.0", "2.0.0-rc.1", "2.0.0", "latest"])
        self.assertEqual(evidence["1.9.0"][0]["id"], "TEST-1")
        self.assertEqual(evidence["2.0.0-rc.1"][0]["id"], "TEST-1")
        self.assertEqual(evidence["2.0.0"], [])
        self.assertNotIn("latest", evidence)
        with self.assertRaisesRegex(ValueError, "unconfirmed"):
            osv_offline.query(self.root, "other", ["1.0.0"])
        with self.assertRaisesRegex(ValueError, "private"):
            osv_offline.query(self.root, "@example/private", ["1.0.0"], "@example", "@example/private")

    def test_pinned_plan_becomes_stale_and_new_plan_rechecks_the_pointer(self):
        with patch.dict(os.environ, {"DEPLOOM_RUN_ID": "first"}):
            self.assertEqual(osv_offline.snapshot(self.root)[1]["status"], "ready")
            self.pointer.write_text("{}")
            self.assertEqual(osv_offline.snapshot(self.root)[1]["sha256"], self.digest)
            with patch.object(osv_offline.time, "time", return_value=self.now + 7 * 86400):
                with self.assertRaisesRegex(ValueError, "stale"):
                    osv_offline.query(self.root, "example", ["1.0.0"])
        with patch.dict(os.environ, {"DEPLOOM_RUN_ID": "second"}):
            self.assertEqual(osv_offline.snapshot(self.root)[1]["status"], "unavailable")

    def test_range_boundaries_and_unsupported_evidence(self):
        version = osv_offline.parse("2.0.0+build")
        def applies(end):
            return osv_offline.matches(version, [], [["SEMVER", [{"introduced": "0"}, {end: "2.0.0"}]]])
        self.assertTrue(applies("last_affected"))
        self.assertFalse(applies("fixed"))
        self.assertFalse(applies("limit"))
        self.assertTrue(osv_offline.matches(version, ["2.0.0+build"], [], raw_version="2.0.0+build"))
        with self.assertRaisesRegex(ValueError, "unsupported"):
            osv_offline.matches(version, ["2.0.0+build"], [], raw_version="2.0.0+different")
        with self.assertRaisesRegex(ValueError, "unsupported"):
            osv_offline.matches(version, [], [["GIT", [{"introduced": "0"}]]])

    def test_blocking_reasons_belong_to_exact_versions(self):
        db = self.root / (self.digest + ".sqlite")
        with closing(sqlite3.connect(db)) as conn:
            conn.executemany("INSERT INTO advisory VALUES (?,?,?,?,?)", [
                ("uncertain", "TEST-2", "low", "[]", '[["GIT",[{"introduced":"0"}]]]'),
                ("unrated", "TEST-3", None, '["1.0.0"]', "[]"),
            ])
            conn.commit()
        versions = ["1.0.0", "2.0.0"]
        self.assertEqual(osv_offline.assess(self.root, "uncertain", versions)["1.0.0"].reason,
                         "UNSUPPORTED_OSV_RANGE")
        unrated = osv_offline.assess(self.root, "unrated", versions)
        self.assertEqual(unrated["1.0.0"].reason, "MISSING_SEVERITY")
        self.assertEqual(unrated["1.0.0"].findings, {"TEST-3": ""})
        self.assertFalse(unrated["2.0.0"].reason)
        self.assertEqual(osv_offline.assess(self.root, "other", versions)["1.0.0"].reason,
                         "PUBLIC_PACKAGE_UNCONFIRMED")
        self.assertFalse(osv_offline.assess(self.root, "other", versions, public_names="first, other")["1.0.0"].reason)
        self.assertEqual(osv_offline.assess(self.root, "@team/one", versions, "@x, @team", "@team/one")["1.0.0"].reason,
                         "PRIVATE_SCOPE_EXCLUDED")
        self.assertEqual(osv_offline.assess(self.root, "example", ["latest"])["latest"].reason,
                         "INVALID_EXACT_VERSION")
        db.write_bytes(b"!" * db.stat().st_size)
        self.assertEqual(osv_offline.assess(self.root, "other", versions, public_names="other")["1.0.0"].reason,
                         "SNAPSHOT_READ_ERROR")

    def test_corporate_fallback_queries_only_exact_gaps_and_preserves_positive_ids(self):
        import dependency_live_roadmap_generator as core
        from unittest.mock import MagicMock
        registry = "https://registry.example.test/repository/npm"
        ghsa = "GHSA-2222-3333-4444"
        with closing(sqlite3.connect(self.root / (self.digest + ".sqlite"))) as conn:
            conn.execute("INSERT INTO advisory VALUES (?,?,?,?,?)",
                         ("example", ghsa, None, '["1.0.0"]', "[]"))
            conn.commit()
        client = core.LiveDataClient(registry, timeout=2, batch_size=16, sleep_sec=0)
        self.addCleanup(client.session.close)
        client.session.post = MagicMock()
        response = client.session.post.return_value.__enter__.return_value
        response.status_code = 200
        response.iter_content.return_value = [json.dumps({"example": [
            {"id": 9, "severity": "high", "url": "https://github.com/advisories/" + ghsa.lower(),
             "vulnerable_versions": "1.0.0"},
            {"id": 9, "severity": "moderate", "vulnerable_versions": "1.0.0"},
            {"id": "CVE-2026-12345", "severity": "critical", "url": "https://github.com/advisories/" + ghsa,
             "vulnerable_versions": "1.0.0"},
        ]}).encode()]
        env = {"DEPLOOM_DRAFT_OSV_DIR": str(self.root), "DEPLOOM_DRAFT_DISABLE_EXTERNAL_EVIDENCE": "1",
               "DEPLOOM_DRAFT_REGISTRY_ADVISORY_SOURCE": registry, "DEPLOOM_DRAFT_CORPORATE_ADVISORY_SOURCE": registry}
        with patch.dict(os.environ, env), patch("npm_semver_batch.match_npm_semver_many", return_value=[True]):
            diagnostics = {}
            result = client.query_osv_versions("example", ["1.0.0", "2.0.0", "latest"], diagnostics=diagnostics)
            self.assertEqual({item["id"] for item in result["1.0.0"]}, {ghsa, "TEST-1"})
            self.assertEqual(len(result["1.0.0"]), 2)
            self.assertEqual(core.vuln_summary(result["1.0.0"]), "C:1, H:1")
            self.assertEqual(diagnostics["1.0.0"]["findingCount"], 2)
            self.assertEqual(diagnostics["1.0.0"]["source"], "OFFLINE_OSV_NPM_AND_REGISTRY")
            self.assertEqual(diagnostics["1.0.0"]["osvReason"], "MISSING_SEVERITY")
            self.assertEqual(result["2.0.0"], [])
            self.assertEqual(diagnostics["2.0.0"], {"status": "ASSESSED", "source": "OFFLINE_OSV_NPM", "findingCount": 0})
            self.assertEqual(diagnostics["latest"]["reason"], "INVALID_EXACT_VERSION")
            self.assertEqual(client.session.post.call_args.kwargs["json"], {"example": ["1.0.0"]})
            self.assertFalse(client.session.post.call_args.kwargs["allow_redirects"])

            # A successful zero for this exact package cannot erase the known, unrated finding.
            response.iter_content.return_value = [b'{"example":[]}']
            with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                client.query_osv_versions("example", ["1.0.0"], diagnostics=diagnostics)
            self.assertEqual(diagnostics["1.0.0"]["reason"], "MISSING_SEVERITY")
            # HTTP 200 without this requested package confirms no coverage.
            response.iter_content.return_value = [b'{}']
            with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                client.query_osv_versions("missing", ["2.0.0"], diagnostics={})
            response.iter_content.return_value = [b'{"missing":[]}']
            self.assertEqual(client.query_osv_versions("missing", ["2.0.0"]), {"2.0.0": []})

    def test_public_fallback_requires_proven_exact_pair_and_only_fills_gaps(self):
        import dependency_live_roadmap_generator as core
        from registry_advisory_evidence import RegistryAdvisoryEvidence

        name, version = "lodash", "4.17.20"
        registry = core.PUBLIC_NPM_REGISTRY
        client = core.LiveDataClient(registry, timeout=2, batch_size=10, sleep_sec=0)
        self.addCleanup(client.session.close)
        meta = core.DirectRegistryPackument(name=name, versions={version: {
            "name": name, "version": version, "dist": {"tarball": f"{registry}/{name}/-/{name}-{version}.tgz"}}})
        client.npm_cache[name] = meta
        env = {"DEPLOOM_DRAFT_OSV_DIR": str(self.root / "absent"),
               "DEPLOOM_DRAFT_PUBLIC_ADVISORY_FALLBACK": "1"}
        reply = {(name, version): RegistryAdvisoryEvidence("NO_REPORTED_ADVISORIES", "REGISTRY_EXACT_VERSION")}
        with patch.dict(os.environ, env), patch.object(client, "metadata_request_context",
                return_value=(client._metadata_request_context, True)), patch.object(
                client, "query_registry_advisory_evidence", return_value=reply) as bulk:
            def query(**kwargs):
                return client.query_osv_versions(name, [version, "8.8.8", "latest"], diagnostics={}, **kwargs)
            self.assertEqual(query(public_fallback=True), {version: []})
            bulk.assert_called_once_with([(name, version)], registry, anonymous_public=True)
            bulk.reset_mock()
            with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                query(public_fallback=True, excluded_public_version=version)
            with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                query()
            with patch.dict(os.environ, {"DEPLOOM_DRAFT_PRIVATE_SCOPES": name}):
                with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                    query(public_fallback=True)
            with patch.dict(client.npm_cache, {name: dict(meta)}):
                with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                    query(public_fallback=True)
            with patch.dict(os.environ, {"DEPLOOM_DRAFT_OSV_DIR": str(self.root)}):
                self.assertEqual(query(public_fallback=True), {version: []})
            bulk.assert_not_called()

    def test_corporate_omission_only_for_confirmed_registry_version(self):
        import dependency_live_roadmap_generator as core
        from unittest.mock import MagicMock
        registry = "https://registry.example.test/npm"
        name = "@team/sample"
        version = "1.0.0"
        client = core.LiveDataClient(registry, timeout=2, batch_size=8, sleep_sec=0)
        self.addCleanup(client.session.close)
        client.npm_cache[name] = {"name": name, "versions": {version: {"name": name, "version": version,
            "dist": {"tarball": registry + "/@team/sample/-/sample-1.0.0.tgz"}}}}
        client.session.post = MagicMock()
        response = client.session.post.return_value.__enter__.return_value
        response.status_code = 200
        response.iter_content.return_value = [b"{}"]
        env = {"DEPLOOM_DRAFT_OSV_DIR": str(self.root), "DEPLOOM_DRAFT_DISABLE_EXTERNAL_EVIDENCE": "1",
               "DEPLOOM_DRAFT_REGISTRY_ADVISORY_SOURCE": registry, "DEPLOOM_DRAFT_CORPORATE_ADVISORY_SOURCE": registry,
               "DEPLOOM_DRAFT_PRIVATE_SCOPES": "@team"}
        with patch.dict(os.environ, env):
            diagnostics = {}
            self.assertEqual(client.query_osv_versions(name, [version, "2.0.0"], diagnostics=diagnostics), {version: []})
            self.assertEqual(diagnostics[version]["source"], "REGISTRY_BULK_ADVISORY")
            self.assertEqual(diagnostics[version]["findingCount"], 0)
            self.assertEqual(diagnostics["2.0.0"]["registryReason"], "COVERAGE_UNCONFIRMED")
            response.status_code = 503
            with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                client.query_osv_versions(name, [version])

    def test_offline_names_never_reach_public_or_unapproved_endpoints(self):
        import dependency_live_roadmap_generator as core
        registry = "https://example.test/corporate"
        private = "@team/private"
        for selected, approval, corporate, restricted in (
            (registry, registry, "", "1"), (registry, registry + "/other", registry, "1"),
            (registry, registry, registry, "0"),
            *[(public, public, public, "1") for public in (
                "https://registry.npmjs.org", "https://Registry.Yarnpkg.com.:443/npm",
                "https://registry.npmjs．org")],
        ):
            with self.subTest(selected=selected, approval=approval, restricted=restricted):
                client = core.LiveDataClient(selected, timeout=2, batch_size=16, sleep_sec=0)
                self.addCleanup(client.session.close)
                env = {"DEPLOOM_DRAFT_OSV_DIR": str(self.root), "DEPLOOM_DRAFT_DISABLE_EXTERNAL_EVIDENCE": restricted,
                       "DEPLOOM_DRAFT_REGISTRY_ADVISORY_SOURCE": approval, "DEPLOOM_DRAFT_CORPORATE_ADVISORY_SOURCE": corporate,
                       "DEPLOOM_DRAFT_PUBLIC_NAMES": private, "DEPLOOM_DRAFT_PRIVATE_SCOPES": "@team"}
                with patch.dict(os.environ, env), patch.object(client.session, "request") as request:
                    diagnostics = {}
                    with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                        client.query_osv_versions(private, ["1.0.0"], diagnostics=diagnostics)
                    self.assertEqual(diagnostics["1.0.0"]["reason"], "PRIVATE_SCOPE_EXCLUDED")
                    request.assert_not_called()


    def test_direct_osv_id_and_strongest_rating_survive_reconciliation(self):
        from registry_advisory_evidence import RegistryAdvisory, RegistryAdvisoryEvidence
        known = osv_offline.PairAssessment({"MAL-2026-1": "", "TEST-OTHER": "critical"}, "MISSING_SEVERITY")
        record = RegistryAdvisoryEvidence("AFFECTED", "REGISTRY_EXACT_VERSION", (
            RegistryAdvisory("MAL-2026-1", "low", "*"),
            RegistryAdvisory("MAL-2026-1", "high", "*"),
            RegistryAdvisory("TEST-OTHER", "low", "*"),
        ))
        merged = osv_offline.supplement(known, record)
        self.assertFalse(merged.reason)
        self.assertEqual(merged.findings, {"MAL-2026-1": "high", "TEST-OTHER": "critical"})

    def test_published_rows_explain_exact_zero_unresolved_range_and_fixed_source(self):
        import dependency_live_roadmap_generator as core
        registry = "https://example.test/npm"
        project = core.ProjectSpec("synthetic", self.root)
        declarations = {"confirmed": "1.0.0", "ranged": "^1.0.0", "local": "file:../local"}
        (self.root / "package.json").write_text(json.dumps({"name": "synthetic", "dependencies": declarations}))
        client = core.LiveDataClient(registry, timeout=2, batch_size=10, sleep_sec=0)
        self.addCleanup(client.session.close)
        client.set_deadline(core.DeadlineClock(None))
        client._metadata_request_context = client.metadata_request_context()[0]
        for name in ("confirmed", "ranged"):
            client.npm_cache[name] = {"name": name, "dist-tags": {"latest": "1.0.0"}, "versions": {
                "1.0.0": {"dist": {"tarball": f"{registry}/{name}/-/{name}-1.0.0.tgz"}}}}
        with patch.dict(os.environ, {"DEPLOOM_DRAFT_OSV_DIR": str(self.root),
                                     "DEPLOOM_DRAFT_PUBLIC_NAMES": "confirmed,ranged"}), patch.object(
                client.session, "request", side_effect=AssertionError("unexpected network")):
            rows = core.analyze_project(project, client, {}, False, 2, tolerate_registry_failure=True)
            core.enrich_final_registry_security({"synthetic": rows}, client, "")
            health = core.compute_project_health(rows, "synthetic", None)
            plan = core.build_draft_plan({"synthetic": rows}, {"synthetic": project}, {"synthetic": health})
        evidence = {row["package"]: row["currentSecurityEvidence"] for row in plan["proposals"][0]["rows"]}
        self.assertEqual(evidence["confirmed"], {"status": "ASSESSED", "source": "OFFLINE_OSV_NPM", "findingCount": 0})
        self.assertEqual(evidence["ranged"], {"status": "UNKNOWN", "reason": "CURRENT_VERSION_UNRESOLVED"})
        self.assertEqual(evidence["local"], {"status": "UNKNOWN", "reason": "NON_REGISTRY_SPEC"})

    def test_private_worker_and_secondary_lookups_require_the_approved_metadata_route(self):
        import dependency_live_roadmap_generator as core
        registry = "https://fixture.example.test/npm"
        private = "@internal/dynamic-peer"
        for offline in ("", str(self.root)):
            for selected, approved, restricted in (
                ("https://registry.npmjs.org", "https://registry.npmjs.org", "1"),
                (registry, registry + "/other", "1"), (registry, "", "1"), (registry, registry, "0"),
            ):
                env = {"DEPLOOM_DRAFT_OSV_DIR": offline, "DEPLOOM_DRAFT_PRIVATE_SCOPES": "@public, @Internal",
                       "DEPLOOM_DRAFT_PRIVATE_METADATA_REGISTRY": approved, "DEPLOOM_DRAFT_DISABLE_EXTERNAL_EVIDENCE": restricted,
                       "DEPLOOM_DRAFT_REGISTRY_ADVISORY_SOURCE": selected}
                with self.subTest(offline=bool(offline), selected=selected, restricted=restricted), patch.dict(os.environ, env):
                    client = core.LiveDataClient(selected, timeout=2, batch_size=16, sleep_sec=0)
                    self.addCleanup(client.session.close)
                    worker = core._registry_prefetch_client(client)
                    self.addCleanup(worker.session.close)
                    with patch.object(worker.session, "request") as request:
                        # Includes names first discovered after the project preflight.
                        with self.assertRaisesRegex(core.RegistryInfrastructureError, "PRIVATE_METADATA"):
                            worker._fetch_npm_metadata_result(private)
                        self.assertEqual(worker.registry_exact_version_manifest(private, "1.0.0")[1],
                                         "PRIVATE_METADATA_REGISTRY_UNAPPROVED")
                        with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                            worker.query_osv_versions(private, ["1.0.0"])
                        self.assertEqual(worker.query_registry_advisory_evidence([(private, "1.0.0")], selected)
                                         [private, "1.0.0"].status, "UNKNOWN")
                        release = worker.fetch_release_intelligence(private, {"repository": "https://github.com/example/private"},
                                                                   "1.0.0", "2.0.0")
                        self.assertEqual(release.status, "unavailable")
                        request.assert_not_called()

    def test_approved_private_metadata_does_not_require_or_imply_advisory_approval(self):
        import dependency_live_roadmap_generator as core
        registry = "https://fixture.example.test/npm"
        private = "@internal/example"
        for offline in ("", str(self.root)):
            env = {"DEPLOOM_DRAFT_OSV_DIR": offline, "DEPLOOM_DRAFT_PRIVATE_SCOPES": "@internal",
                   "DEPLOOM_DRAFT_PRIVATE_METADATA_REGISTRY": registry, "DEPLOOM_DRAFT_DISABLE_EXTERNAL_EVIDENCE": "1",
                   "DEPLOOM_DRAFT_REGISTRY_ADVISORY_SOURCE": "", "DEPLOOM_DRAFT_CORPORATE_ADVISORY_SOURCE": ""}
            with self.subTest(offline=bool(offline)), patch.dict(os.environ, env):
                client = core.LiveDataClient(registry, timeout=2, batch_size=16, sleep_sec=0)
                self.addCleanup(client.session.close)
                worker = core._registry_prefetch_client(client)
                self.addCleanup(worker.session.close)
                with patch.object(worker.session, "get") as get, patch.object(worker, "_bounded_json", return_value={
                    "name": private, "versions": {"1.0.0": {"dist": {"tarball": registry + "/example.tgz"}}},
                    "dist-tags": {"latest": "1.0.0"},
                }), patch.object(worker.session, "post") as post:
                    get.return_value.status_code = 200
                    get.return_value.headers = {}
                    self.assertEqual(worker.fetch_npm_metadata(private)["name"], private)
                    self.assertFalse(get.call_args.kwargs["allow_redirects"])
                    with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                        worker.query_osv_versions(private, ["1.0.0"])
                    post.assert_not_called()
