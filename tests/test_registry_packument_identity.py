"""Bind live and cached registry metadata to the requested package/version.

All HTTP traffic stays on a real loopback server. No public registry, OSV,
installation, or project scripts are involved.
"""
from __future__ import annotations

import copy
import http.server
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import dependency_live_roadmap_generator as core
from registry_metadata_cache import _entry_path, store_packument


PACKAGE = "requested-package"
VERSION = "9.9.9"


class RegistryPackumentIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache = self.root / "cache"
        self.responses = []
        self.requests = []
        test = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                test.requests.append({
                    "path": self.path,
                    "ifNoneMatch": self.headers.get("If-None-Match"),
                    "ifModifiedSince": self.headers.get("If-Modified-Since"),
                })
                if not test.responses:
                    self.send_response(500)
                    self.end_headers()
                    return
                response = test.responses.pop(0)
                body = json.dumps(response.get("body", {})).encode("utf-8")
                self.send_response(response.get("status", 200))
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for name, value in response.get("headers", {}).items():
                    self.send_header(name, value)
                self.end_headers()
                if response.get("status", 200) != 304:
                    self.wfile.write(body)

            def log_message(self, *_args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        self.registry = f"http://127.0.0.1:{self.server.server_port}"

    def _stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def _client(self):
        client = core.LiveDataClient(
            self.registry, timeout=2, batch_size=8, sleep_sec=0,
            metadata_cache_dir=self.cache, metadata_cache_ttl=600,
            metadata_cache_tool_version="identity-regression",
        )
        self.addCleanup(client.session.close)
        return client

    def _packument(self, name=PACKAGE):
        return {
            "name": name,
            "dist-tags": {"latest": VERSION},
            "versions": {VERSION: {
                "name": name,
                "version": VERSION,
                "dist": {"tarball": f"{self.registry}/{name}/-/{name}-{VERSION}.tgz"},
            }},
        }

    def _mismatch(self, kind):
        value = self._packument()
        if kind == "root-name":
            value["name"] = "different-package"
        elif kind == "manifest-name":
            value["versions"][VERSION]["name"] = "different-package"
        elif kind == "manifest-version":
            value["versions"][VERSION]["version"] = "8.8.8"
        else:
            raise AssertionError(kind)
        return value

    def _legacy_entry(self, client, value, *, age=0):
        # Seed a valid envelope, then simulate bytes left by an older producer.
        context = client.metadata_request_context()[0]
        store_packument(
            self.cache, self.registry, PACKAGE, self._packument(),
            context=context, now=time.time() - age,
            validators={"ETag": '"identity-old"'},
        )
        path = _entry_path(self.cache, self.registry, PACKAGE, context)
        entry = json.loads(path.read_text(encoding="utf-8"))
        entry["data"] = copy.deepcopy(value)
        path.write_text(json.dumps(entry), encoding="utf-8")
        return path, entry

    def _assert_live_mismatch(self, kind, reason):
        self.responses.append({"body": self._mismatch(kind)})
        client = self._client()
        with self.assertRaises(core.RegistryInfrastructureError) as failed:
            client.fetch_npm_metadata(PACKAGE)
        self.assertEqual(reason, getattr(failed.exception, "code", None))
        self.assertIn(reason, str(failed.exception))
        self.assertNotIn("different-package", str(failed.exception))
        self.assertNotIn(PACKAGE, client.npm_cache)
        self.assertEqual([], list(self.cache.rglob("*.json")))
        self.assertEqual(1, len(self.requests))

    def test_live_root_name_mismatch_is_typed_and_not_cached(self):
        self._assert_live_mismatch("root-name", "REGISTRY_PACKAGE_IDENTITY_MISMATCH")

    def test_live_manifest_name_mismatch_is_typed_and_not_cached(self):
        self._assert_live_mismatch("manifest-name", "REGISTRY_PACKAGE_IDENTITY_MISMATCH")

    def test_live_manifest_version_mismatch_is_typed_and_not_cached(self):
        self._assert_live_mismatch("manifest-version", "REGISTRY_VERSION_IDENTITY_MISMATCH")

    def test_matching_identity_retains_latest_and_cross_client_cache(self):
        expected = self._packument()
        self.responses.append({"body": expected})
        first = self._client()
        metadata = first.fetch_npm_metadata(PACKAGE)
        first.draft = True
        self.assertEqual(VERSION, first.latest_installable_version(
            PACKAGE, metadata, include_prerelease=False, current="1.0.0"))
        second = self._client()
        self.assertEqual(expected, second.fetch_npm_metadata(PACKAGE))
        self.assertEqual((1, 0), second.metadata_cache_stats())
        self.assertEqual(1, len(self.requests))

    def test_absent_optional_identity_fields_remain_supported(self):
        expected = self._packument()
        del expected["name"]
        del expected["versions"][VERSION]["name"]
        del expected["versions"][VERSION]["version"]
        self.responses.append({"body": expected})
        self.assertEqual(expected, self._client().fetch_npm_metadata(PACKAGE))
        self.assertEqual(expected, self._client().fetch_npm_metadata(PACKAGE))
        self.assertEqual(1, len(self.requests))

    def test_old_invalid_memory_entry_is_evicted_before_live_recovery(self):
        expected = self._packument()
        self.responses.append({"body": expected})
        client = self._client()
        client.npm_cache[PACKAGE] = self._mismatch("manifest-name")
        self.assertEqual(expected, client.fetch_npm_metadata(PACKAGE))
        self.assertEqual(expected, client.npm_cache[PACKAGE])
        self.assertEqual(1, len(self.requests))

    def test_old_invalid_disk_entry_is_a_miss_and_can_recover(self):
        client = self._client()
        self._legacy_entry(client, self._mismatch("root-name"))
        expected = self._packument()
        self.responses.append({"body": expected})
        self.assertEqual(expected, client.fetch_npm_metadata(PACKAGE))
        self.assertEqual((0, 1), client.metadata_cache_stats())
        self.assertEqual(1, len(self.requests))
        self.assertIsNone(self.requests[0]["ifNoneMatch"])
        self.assertEqual(expected, self._client().fetch_npm_metadata(PACKAGE))
        self.assertEqual(1, len(self.requests))

    def test_invalid_stale_subject_cannot_be_renewed_by_304(self):
        client = self._client()
        path, original = self._legacy_entry(
            client, self._mismatch("manifest-version"), age=601)
        self.responses.append({"status": 304})
        with self.assertRaises(core.RegistryInfrastructureError) as failed:
            client.fetch_npm_metadata(PACKAGE)
        self.assertEqual("REGISTRY_VERSION_IDENTITY_MISMATCH", getattr(failed.exception, "code", None))
        self.assertNotIn(PACKAGE, client.npm_cache)
        self.assertEqual(1, len(self.requests))
        self.assertIsNone(self.requests[0]["ifNoneMatch"])
        self.assertIsNone(self.requests[0]["ifModifiedSince"])
        self.assertEqual(original, json.loads(path.read_text(encoding="utf-8")))

    def test_matching_stale_subject_still_revalidates_with_304(self):
        client = self._client()
        expected = self._packument()
        path, original = self._legacy_entry(client, expected, age=601)
        self.responses.append({"status": 304})
        self.assertEqual(expected, client.fetch_npm_metadata(PACKAGE))
        self.assertEqual('"identity-old"', self.requests[0]["ifNoneMatch"])
        self.assertGreater(json.loads(path.read_text())["fetchedAtUnix"], original["fetchedAtUnix"])
        self.assertEqual(expected, self._client().fetch_npm_metadata(PACKAGE))
        self.assertEqual(1, len(self.requests))

    def test_draft_publishes_typed_unknown_without_a_target(self):
        project_root = self.root / "project"
        project_root.mkdir()
        (project_root / "package.json").write_text(json.dumps({
            "name": "fixture", "dependencies": {PACKAGE: "1.0.0"},
        }), encoding="utf-8")
        self.responses.append({"body": self._mismatch("manifest-name")})
        client = self._client()
        client.draft = True
        project = core.ProjectSpec("fixture", project_root)
        # Cover prefetch workers as well as the original client, including on
        # the broken baseline where invalid metadata would otherwise reach OSV.
        with patch.object(core.LiveDataClient, "query_osv_versions", return_value={}) as osv:
            rows = core.analyze_project(project, client, {}, False, 2, tolerate_registry_failure=True)
        self.assertEqual(1, len(rows))
        self.assertEqual("registry-failed", rows[0].draft_unknown)
        self.assertEqual({"status": "UNKNOWN", "reason": "REGISTRY_PACKAGE_IDENTITY_MISMATCH"},
                         rows[0].current_security_evidence)
        self.assertEqual("registry unavailable", rows[0].latest_version)
        self.assertFalse(core.target_is_action(rows[0].target_green))
        osv.assert_not_called()
        self.assertEqual(1, len(self.requests))
        self.assertEqual([], list(self.cache.rglob("*.json")))

    def test_prefetch_rejects_old_invalid_disk_subject_before_planning(self):
        client = self._client()
        self._legacy_entry(client, self._mismatch("manifest-name"))
        expected = self._packument()
        self.responses.append({"body": expected})
        core._prefetch_registry_metadata(client, [(PACKAGE, "prod", "1.0.0")])
        self.assertEqual(expected, client.npm_cache[PACKAGE])
        self.assertEqual(1, len(self.requests))


if __name__ == "__main__":
    unittest.main()
