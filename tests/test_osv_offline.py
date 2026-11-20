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
            with patch.object(osv_offline.time, "time", return_value=self.now + 8 * 86400):
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
        with self.assertRaisesRegex(ValueError, "unsupported"):
            osv_offline.matches(version, [], [["GIT", [{"introduced": "0"}]]])
