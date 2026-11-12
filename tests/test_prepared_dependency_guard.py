"""Continuity checks for the shared installed tree on Windows."""
import os
from pathlib import Path
import stat
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import prepared_workspace_fastpath as fastpath
from reparse_materialization import ReparseLink, recreate_reparse_plan


@unittest.skipUnless(os.name == "nt", "ReadDirectoryChangesW is Windows-specific")
class DependencyTreeGuardTests(unittest.TestCase):
    def test_checks_clean_root_then_observes_write_at_final_boundary(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "node_modules"
            root.mkdir()
            guard = fastpath._DependencyTreeGuard([root])
            self.assertTrue(guard.start())
            try:
                self.assertEqual(guard.drain(), ())
                (root / "late.txt").write_bytes(b"changed")
            finally:
                result = guard.stop()
            self.assertEqual(result.errors, ())
            self.assertTrue(any(row.endswith(":late.txt") for row in result.notification_only))
            self.assertFalse(any(".deploom-drain-" in row for row in result.notification_only))
            self.assertEqual(list(root.glob(".deploom-drain-*")), [])

    def test_workspace_guard_reports_a_write_at_its_final_boundary(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            guard = fastpath.WorkspaceChangeGuard(root)
            self.assertTrue(guard.start())
            try:
                (root / "changed.txt").write_bytes(b"changed")
            finally:
                result = guard.stop()
            self.assertFalse(result.errors)
            self.assertTrue(any(event.endswith(":changed.txt") for event in result.changes))
            self.assertFalse(any(".dependency-roadmap" in event for event in result.changes))

    def test_local_install_burst_preserves_notifications_after_a_delayed_read(self):
        release = threading.Event()

        class PausableWatcher(fastpath._DirectoryWatcher):
            def __init__(self, root, *, reserve_write_bursts):
                super().__init__(root, reserve_write_bursts=reserve_write_bursts)
                self.waiting = threading.Event()

            def _consume(self, size):
                if not self.waiting.is_set():
                    self.waiting.set()
                    release.wait(15)
                super()._consume(size)

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            regular = PausableWatcher(root, reserve_write_bursts=False)
            burst = PausableWatcher(root, reserve_write_bursts=True)
            try:
                self.assertTrue(regular.start(), regular.errors)
                self.assertTrue(burst.start(), burst.errors)
                if len(burst._buffer) == len(regular._buffer):
                    self.skipTest("The workspace is not on a fixed local drive")
                (root / "wake").mkdir()
                self.assertTrue(regular.waiting.wait(5))
                self.assertTrue(burst.waiting.wait(5))
                names = {f"{index:04d}-{'d' * 96}" for index in range(800)}
                for name in sorted(names):
                    (root / name).mkdir()
                release.set()
                delivered, _ = fastpath.drain_watcher(burst, root)
                self.assertTrue(delivered, burst.errors)
                observed = {name for action, name in burst.events if action == burst.FILE_ACTION_ADDED}
                self.assertTrue(names <= observed, sorted(names - observed)[:3])
            finally:
                release.set()
                regular.stop()
                burst.stop()
            self.assertTrue(any("overflow" in error for error in regular.errors), regular.errors)
            self.assertFalse(burst.errors)

    def test_stopping_a_watcher_immediately_keeps_handles_valid(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for _ in range(32):
                watcher = fastpath._DirectoryWatcher(root)
                self.assertTrue(watcher.start())
                watcher.stop(drained=True)
                self.assertFalse(watcher.errors)
                self.assertFalse(watcher._thread.is_alive())

    def test_workspace_guard_rejects_an_identity_change_during_its_barrier(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            guard = fastpath.WorkspaceChangeGuard(root)
            self.assertTrue(guard.start())
            identity = fastpath.tree_object_identity(root)
            with patch.object(fastpath, "tree_object_identity", side_effect=[identity, (0, 1)]):
                result = guard.stop()
            self.assertIn("private trial root identity changed", result.errors)

    def test_missing_dependency_barrier_blocks_clean_result(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "node_modules"
            root.mkdir()
            guard = fastpath._DependencyTreeGuard([root])
            self.assertTrue(guard.start())
            with patch.object(fastpath, "drain_watcher", return_value=(False, ".lost-token")):
                result = guard.stop()
            self.assertTrue(any("Dependency watcher drain unconfirmed" in row for row in result.errors))

    def test_private_workspace_copy_rebases_junction_to_private_owner(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            private = root / "private space"
            owner = Path("packages") / "owner % \u03a9"
            (source / owner).mkdir(parents=True)
            (private / owner).mkdir(parents=True)
            link_relative = Path("node_modules") / "workspace-owner"
            link = private / link_relative
            try:
                recreate_reparse_plan(source, private, [
                    ReparseLink(link_relative.as_posix(), owner.as_posix(), "junction", "workspace")
                ])
                self.assertTrue(fastpath.is_windows_junction(link))
                self.assertEqual(link.resolve(strict=True), (private / owner).resolve(strict=True))
            finally:
                if fastpath.is_windows_junction(link):
                    link.rmdir()

    def test_junction_batch_resolves_exact_unicode_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "package \u03a9"
            target.mkdir()
            link = root / "trial space" / "workspace % package"
            try:
                self.assertTrue(fastpath._create_junction_batch([(link, target)]))
                self.assertTrue(fastpath.is_windows_junction(link))
                self.assertEqual(link.resolve(strict=True), target.resolve(strict=True))
                self.assertFalse(fastpath._create_junction_batch([(link, target)]))
            finally:
                if fastpath.is_windows_junction(link):
                    link.rmdir()

    def test_esbuild_loader_and_windows_binary_are_private(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            lower = root / "lower"
            clone = root / "clone"
            for name in ("esbuild/lib/main.js", "@esbuild/win32-x64/esbuild.exe", "unrelated/index.js"):
                path = lower / "node_modules" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())
            ok, junctions = fastpath._populate_node_modules_shell(
                lower / "node_modules", clone / "node_modules",
                prepared_workspace_root=lower, clone_workspace_root=clone, reparse_plan=(),
            )
            try:
                self.assertTrue(ok)
                self.assertEqual(junctions, [clone / "node_modules/unrelated"])
                for name in ("esbuild/lib/main.js", "@esbuild/win32-x64/esbuild.exe"):
                    relative = Path("node_modules") / name
                    path = clone / relative
                    self.assertEqual(path.resolve(strict=True), path)
                    self.assertEqual(path.read_bytes(), (lower / relative).read_bytes())
                    path.write_bytes(b"private mutation")
                    self.assertEqual((lower / relative).read_bytes(), name.encode())
            finally:
                for link in junctions:
                    link.rmdir()

    def test_write_protection_skips_file_reparse_points(self):
        root = Path("sealed")
        regular = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_file_attributes=0)
        reparse = SimpleNamespace(st_mode=stat.S_IFREG | 0o644,
                                  st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        with patch.object(fastpath.os, "walk", return_value=[(root, [], ["link", "plain"])]), patch.object(
                fastpath.os, "stat", side_effect=[reparse, regular]), patch.object(fastpath.os, "chmod") as chmod:
            self.assertEqual(fastpath.apply_tree_write_protection(root, readonly=True), 1)
        chmod.assert_called_once_with(root / "plain", stat.S_IFREG | 0o444)
