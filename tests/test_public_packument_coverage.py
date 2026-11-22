"""Actual metadata request provenance and exact-version public OSV coverage."""
import json
import os
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import requests

import dependency_live_roadmap_generator as core
from lockfile_consistency import direct_public_lock_records
from public_npm_identity import PUBLIC_NPM_REGISTRY, matches_lock


class PublicPackumentCoverageTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        digest = "b" * 64
        db = self.root / (digest + ".sqlite")
        with closing(sqlite3.connect(db)) as conn:
            conn.execute("CREATE TABLE advisory(name, id, severity, versions, ranges)")
        self.pointer = self.root / "active.json"
        self.manifest = dict(schema=1, ecosystem="npm", sha256=digest, unpacked=db.stat().st_size, published=int(time.time()))
        self.pointer.write_text(json.dumps(self.manifest))
        env = patch.dict(os.environ, {"DEPLOOM_DRAFT_OSV_DIR": str(self.root),
                                      "DEPLOOM_DRAFT_PUBLIC_NAMES": "", "DEPLOOM_DRAFT_PRIVATE_SCOPES": ""})
        env.start()
        self.addCleanup(env.stop)
        self.name, self.version = "@sample/demo", "2.0.0"
        self.url = PUBLIC_NPM_REGISTRY + "/@sample%2Fdemo"
        self.dist = {"tarball": PUBLIC_NPM_REGISTRY + "/@sample/demo/-/demo-2.0.0.tgz",
                     "integrity": "sha512-" + "A" * 86 + "==", "shasum": "c" * 40}
        self.record = {"name": self.name, "version": self.version, "dist": self.dist}
        self.data = {"name": self.name, "versions": {self.version: self.record}}

    def client(self, registry=PUBLIC_NPM_REGISTRY):
        client = core.LiveDataClient(registry, timeout=2, batch_size=5, sleep_sec=0,
                                     metadata_cache_dir=self.root / "cache", metadata_cache_ttl=20)
        self.addCleanup(client.session.close)
        return client

    def response(self, status=200):
        response = requests.Response()
        response.status_code = status
        response.url = self.url
        response.request = requests.Request("GET", self.url).prepare()
        response.headers["ETag"] = '"v1"'
        response._content = json.dumps(self.data).encode()
        response._content_consumed = True
        return response

    def read(self, client, response):
        with patch.object(client.session, "get", return_value=response) as get:
            client.fetch_npm_metadata(self.name)
        return get.call_args.kwargs

    def coverage(self, client):
        diagnostics = {}
        with patch.object(client.session, "request", side_effect=AssertionError("unexpected security request")):
            try:
                client.query_osv_versions(self.name, [self.version, "2.1.0"], diagnostics=diagnostics)
            except core.VulnerabilityEvidenceUnavailable:
                pass
        return diagnostics

    def test_cold_warm_and_revalidated_marked_cache_confirm_only_exact_public_version(self):
        client = self.client()
        self.read(client, self.response())
        cold = self.coverage(client)
        self.assertEqual(cold[self.version], {"status": "ASSESSED", "source": "OFFLINE_OSV_NPM",
                                              "findingCount": 0, "publicIdentitySource": "NPM_PUBLIC_PACKUMENT"})
        self.assertEqual(cold["2.1.0"]["reason"], "PUBLIC_PACKAGE_UNCONFIRMED")
        withheld = {}
        with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
            client.query_osv_versions(self.name, [self.version], excluded_public_version=self.version, diagnostics=withheld)
        self.assertEqual(withheld[self.version]["reason"], "LOCKED_PUBLIC_ARTIFACT_UNCONFIRMED")
        warm = self.client()
        with patch.object(warm.session, "get", side_effect=AssertionError("fresh cache should serve metadata")):
            warm.fetch_npm_metadata(self.name)
        self.assertEqual(self.coverage(warm), cold)
        file = next((self.root / "cache").rglob("*.json"))
        entry = json.loads(file.read_bytes())
        entry["fetchedAtUnix"] -= 40
        file.write_text(json.dumps(entry))
        warmed = self.client()
        self.assertEqual(self.read(warmed, self.response(304))["headers"], {"If-None-Match": '"v1"'})
        self.assertEqual(self.coverage(warmed), cold)
        with patch.dict(os.environ, {"DEPLOOM_DRAFT_PRIVATE_SCOPES": "@Sample"}):
            self.assertEqual(self.coverage(warmed)[self.version]["reason"], "PRIVATE_SCOPE_EXCLUDED")
        self.pointer.write_text(json.dumps({**self.manifest, "published": self.manifest["published"] - 7 * 86400}))
        self.assertEqual(self.coverage(warmed)[self.version]["reason"], "SNAPSHOT_STALE")

    def test_legacy_cache_is_unknown_and_one_unconditional_request_on_expiry_proves_identity(self):
        self.read(self.client(), self.response())
        file = next((self.root / "cache").rglob("*.json"))
        entry = json.loads(file.read_bytes())
        del entry["directAnonymousOrigin"]
        # Putting a boolean inside the packument itself cannot certify its origin.
        entry["data"]["directAnonymousOrigin"] = True
        file.write_text(json.dumps(entry))
        warm = self.client()
        with patch.object(warm.session, "get", side_effect=AssertionError("unexpected registry request")):
            warm.fetch_npm_metadata(self.name)
        self.assertEqual(self.coverage(warm)[self.version]["reason"], "PUBLIC_PACKAGE_UNCONFIRMED")
        entry["fetchedAtUnix"] -= 40
        file.write_text(json.dumps(entry))
        updated = self.client()
        self.assertNotIn("headers", self.read(updated, self.response()))
        self.assertEqual(self.coverage(updated)[self.version]["findingCount"], 0)

    def test_cookie_response_is_ephemeral_and_requires_explicit_public_cache_control(self):
        with patch.dict(os.environ, {"DEPLOOM_DRAFT_PUBLIC_ADVISORY_FALLBACK": "1"}):
            client = self.client()
        for control, expected in (("public, max-age=300", core.AdvisoryOnlyPackument),
                                  ("private, public", dict), ("no-store", dict), ("", dict)):
            with self.subTest(control=control):
                response = self.response()
                response.headers.update({"Set-Cookie": "fixture=offered", "Cache-Control": control})
                with core._stateless_npm_session() as isolated, patch.object(core, "_stateless_npm_session", return_value=isolated), patch.object(isolated, "get", return_value=response) as get:
                    self.assertIs(type(client.fetch_npm_metadata(self.name)), expected)
                    self.assertFalse(get.call_args.kwargs["allow_redirects"])
                self.assertNotIn(self.name, client.npm_cache)
                self.assertFalse(any((self.root / "cache").rglob("*.json")))

    def test_untrusted_transport_never_establishes_identity(self):
        for condition in ("redirect", "mirror", "sent-cookie", "cookie", "auth", "env", "proxy", "missing-request",
                          "private-response", "credential-on-request"):
            with self.subTest(condition=condition):
                client = self.client("https://example.test" if condition == "mirror" else PUBLIC_NPM_REGISTRY)
                client.metadata_cache_dir = None
                response = self.response()
                if condition == "redirect":
                    response.history = [self.response(302)]
                elif condition == "sent-cookie":
                    response.headers["Set-Cookie"] = "foo=bar"
                elif condition == "cookie":
                    client.session.cookies.set("foo", "bar")
                elif condition == "auth":
                    client.session.auth = ("test", "fixture")
                elif condition == "env":
                    client.session.trust_env = True
                elif condition == "proxy":
                    client.session.proxies["https"] = "http://test.invalid"
                elif condition == "missing-request":
                    response.request = None
                elif condition == "private-response":
                    response.headers["Cache-Control"] = "private"
                elif condition == "credential-on-request":
                    response.request.headers["Authorization"] = "test"
                self.read(client, response)
                self.assertEqual(self.coverage(client)[self.version]["reason"], "PUBLIC_PACKAGE_UNCONFIRMED")

    def test_lock_proof_uses_owner_slot_and_exact_yarn_selector(self):
        public = self.data
        foreign = {"name": self.name, "version": self.version, "resolved": "https://foreign.invalid/demo.tgz"}
        direct = {**foreign, "resolved": self.dist["tarball"], "integrity": self.dist["integrity"]}
        manifest_deps = [(self.name, "runtime", "^2.0.0")]
        lock = self.root / "package-lock.json"
        lock.write_text(json.dumps({"packages": {"node_modules/" + self.name: direct,
                                                  "packages/member/node_modules/" + self.name: foreign}}))
        key = self.name, "^2.0.0"
        for project, matches in ((self.root, True), (self.root / "packages/member", False)):
            record = direct_public_lock_records(project, lock, manifest_deps)[key]
            self.assertIs(matches_lock(public, self.name, self.version, record), matches)
        self.assertFalse(matches_lock(public, self.name, self.version, {**direct, "integrity": "sha512-Other"}))
        self.assertFalse(matches_lock(public, self.name, self.version, {**direct, "link": True}))
        lock = self.root / "yarn.lock"
        resolved = self.dist["tarball"].replace("registry.npmjs.org", "registry.yarnpkg.com")
        lock.write_text(f'"{self.name}@^1.0.0":\n  version "1.0.0"\n  resolved "https://foreign.invalid/demo.tgz"\n'
                        f'"{self.name}@^2.0.0":\n  version "2.0.0"\n  resolved "{resolved}#{self.dist["shasum"]}"\n')
        record = direct_public_lock_records(self.root, lock, manifest_deps)[key]
        self.assertTrue(matches_lock(public, self.name, self.version, record))
        self.assertFalse(matches_lock(public, self.name, self.version, {**record, "resolved": resolved}))
        self.assertFalse(matches_lock(public, self.name, self.version, {**record, "name": "different"}))
        berry = {"version": self.version, "resolution": f"{self.name}@npm:{self.version}"}
        self.assertTrue(matches_lock(public, self.name, self.version, berry, yarn=True))
        self.assertFalse(matches_lock(public, self.name, self.version, berry))
