from __future__ import annotations

import multiprocessing
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import constraint_cache as cache_module


def hold_cache(cache, channel):
    with cache_module._exclusive_cache_write_lock(cache):
        channel.send("locked")
        channel.recv()


class ConstraintCacheWindowsLockTests(unittest.TestCase):
    def test_transient_permission_error_without_visible_lock_is_retried(self):
        """A Windows sharing race must be retried, not misclassified as ACL failure."""
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp) / "cache.json"
            original_mkdir = Path.mkdir
            calls = {"count": 0}

            def transient_mkdir(path, *args, **kwargs):
                if str(path).endswith("cache.json.lock") and calls["count"] == 0:
                    calls["count"] += 1
                    raise PermissionError(
                        13,
                        "simulated transient Windows CREATE_NEW sharing race",
                        str(path),
                    )
                return original_mkdir(path, *args, **kwargs)

            with mock.patch.object(
                Path,
                "mkdir",
                new=transient_mkdir,
            ):
                with cache_module._exclusive_cache_write_lock(cache):
                    pass

            self.assertEqual(1, calls["count"])
            self.assertFalse(cache.with_name("cache.json.lock").exists())

    def test_persistent_permission_error_still_fails_closed(self):
        """The grace retry must not turn a real permissions failure into success."""
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp) / "cache.json"

            def denied(path, flags, *args, **kwargs):
                raise PermissionError(
                    13,
                    "simulated persistent ACL failure",
                    str(path),
                )

            with mock.patch.object(cache_module.os, "open", side_effect=denied):
                with self.assertRaises(PermissionError):
                    with cache_module._exclusive_cache_write_lock(cache):
                        pass

    def test_aged_live_guard_excludes_other_writers_and_recovers_after_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp) / "cache.json"
            marker = cache.with_name("cache.json.lock")
            context = multiprocessing.get_context("spawn")
            parent, child = context.Pipe()
            holder = context.Process(target=hold_cache, args=(cache, child))
            holder.start()
            child.close()
            try:
                self.assertTrue(parent.poll(10))
                self.assertEqual(parent.recv(), "locked")
                old = time.time() - 121
                os.utime(marker, (old, old))
                with mock.patch.object(cache_module, "_CACHE_WRITE_TIMEOUT", 0.1):
                    with self.assertRaises(TimeoutError), cache_module._exclusive_cache_write_lock(cache):
                        self.fail("second writer entered while the first still held the guard")
                # Both operations used by the old file-marker protocol must fail.
                with self.assertRaises(OSError):
                    os.close(os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
                with self.assertRaises(OSError):
                    marker.unlink()
            finally:
                holder.kill()
                holder.join(timeout=10)
                parent.close()
            self.assertFalse(holder.is_alive())
            self.assertTrue(marker.is_dir())
            with cache_module._exclusive_cache_write_lock(cache):
                self.assertTrue(marker.is_dir())
            self.assertFalse(marker.exists())

    def test_old_regular_file_marker_is_never_stolen(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp) / "cache.json"
            marker = cache.with_name("cache.json.lock")
            marker.write_text("legacy owner", encoding="ascii")
            old = time.time() - 121
            os.utime(marker, (old, old))
            with mock.patch.object(cache_module, "_CACHE_WRITE_TIMEOUT", 0.1):
                with self.assertRaises(TimeoutError), cache_module._exclusive_cache_write_lock(cache):
                    self.fail("entered while a legacy writer could still be active")
            self.assertEqual(marker.read_text(encoding="ascii"), "legacy owner")
            marker.unlink()
            with cache_module._exclusive_cache_write_lock(cache):
                pass


if __name__ == "__main__":
    unittest.main()
