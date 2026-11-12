"""Lost watcher intervals cannot recover PASS from equal endpoint bytes."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import os,shutil,tempfile,unittest
import source_snapshot as core

class LiveContinuityDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.project=Path(self.temp.name)/'fixture';self.project.mkdir()
        (self.project/'package.json').write_text('{"name":"continuity-test","version":"1.0.0"}',encoding='utf-8')
        (self.project/'source.txt').write_text('original',encoding='utf-8')
    def check_failure(self,*,errors=(),drained=True,alive=True,mutate_restore=False,swap=False,expected):
        with core.verification_source_snapshot_scope(self.project,timeout_seconds=15,strict_cleanup=True) as snapshot:
            root_identity=core._tree_object_identity(self.project)
            if mutate_restore:
                (self.project/'source.txt').write_text('temporary-untrusted',encoding='utf-8')
                (self.project/'source.txt').write_text('original',encoding='utf-8')
            if swap:
                moved=self.project.with_name('replaced-original');self.project.rename(moved)
                shutil.copytree(moved,self.project)
            manifest=core.build_source_tree_manifest(self.project,policy=snapshot.input_policy or core.SourceInputPolicy(),timeout_seconds=10)
            self.assertEqual(manifest.key,snapshot.manifest_key)
            fake=SimpleNamespace(errors=list(errors),events=[(1,'node_modules/generated.js')],
                _thread=SimpleNamespace(is_alive=lambda:alive),stop=lambda:None)
            key=core._active_key(self.project)
            core._LIVE_SOURCE_WATCHERS[key]=(snapshot,fake,root_identity,root_identity)
            with patch.object(core,'_drain_watcher',return_value=drained),patch.object(core,'build_source_tree_manifest',side_effect=AssertionError('lost interval must not rescan into PASS')),patch.object(core,'emit_observability_event') as emit:
                self.assertFalse(core.source_snapshot_live_source_continuity(snapshot,timeout_seconds=5))
            event=next(call.kwargs for call in emit.call_args_list if call.kwargs.get('outcome')=='watcher-invalidated')
            self.assertEqual(event['failureReason'],expected)
            self.assertEqual(event['relevantEventCount'],0)
            self.assertEqual(event['deliveredEventCount'],1)
            self.assertFalse(event['continuityRestored'])
            self.assertEqual(event['finalManifestComparison'],'NOT_RUN_INTERVAL_UNPROVEN')
            self.assertNotIn(str(self.project),repr(event))
            self.assertNotIn(key,core._LIVE_SOURCE_WATCHERS)
    def test_overflow_rejects_equal_endpoint_bytes(self):
        self.check_failure(errors=['ReadDirectoryChangesW buffer overflow for private-path'],expected='OVERFLOW')
    def test_drain_failure_rejects_equal_endpoint_bytes(self):
        self.check_failure(drained=False,expected='DRAIN')
    def test_lost_interval_cannot_hide_transient_source_change(self):
        self.check_failure(errors=['ReadDirectoryChangesW buffer overflow for private-path'],mutate_restore=True,expected='OVERFLOW')
    def test_dead_thread_rejects_equal_endpoint_bytes(self):
        self.check_failure(alive=False,expected='THREAD')
    def test_equal_bytes_after_directory_swap_do_not_preserve_identity(self):
        self.check_failure(swap=True,expected='IDENTITY')
    @unittest.skipUnless(os.name == "nt", "actual Windows recursive watcher boundary")
    def test_capture_reuses_live_manifest_and_detects_late_source_edit(self):
        snapshot = core.capture_source_snapshot(self.project, timeout_seconds=15, _retain_live_watcher=True)
        self.addCleanup(core._retire_completed_request, snapshot)
        with patch.object(core, "build_source_tree_manifest", side_effect=AssertionError("unexpected live rehash")):
            self.assertTrue(core.source_snapshot_live_source_continuity(snapshot, timeout_seconds=5))
        (self.project / "source.txt").write_text("changed", encoding="utf-8")
        self.assertFalse(core.source_snapshot_live_source_continuity(snapshot, timeout_seconds=5))

    @unittest.skipUnless(os.name=='nt','actual Windows recursive watcher boundary')
    def test_actual_excluded_tree_activity_preserves_source_continuity(self):
        with core.verification_source_snapshot_scope(self.project,timeout_seconds=15,strict_cleanup=True) as snapshot:
            self.assertTrue(core.source_snapshot_live_source_continuity(snapshot,timeout_seconds=10))
            output=self.project/'node_modules';output.mkdir()
            for index in range(256):(output/(str(index)+'.js')).write_text('generated',encoding='utf-8')
            self.assertTrue(core.source_snapshot_live_source_continuity(snapshot,timeout_seconds=10))
            (self.project/'source.txt').write_text('changed',encoding='utf-8')
            self.assertFalse(core.source_snapshot_live_source_continuity(snapshot,timeout_seconds=10))

if __name__=='__main__':unittest.main()
