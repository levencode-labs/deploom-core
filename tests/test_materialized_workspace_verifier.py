"""Actual npm/Node checks of the current workspace, not a prepared copy.

No dependencies, registry, agent or MCP are needed. Nonempty physical held
obligations are separately covered by test_npm_dependency_obligations.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

from materialized_workspace_verifier import (verify_current_workspace,
    MaterializedWorkspaceVerificationError)
from resolved_dependency_state import compile_npm_dependency_obligations
from source_snapshot import source_snapshot_fingerprint


def command(body):
    encoded=base64.b64encode(body.encode()).decode()
    return 'node -e '+json.dumps("eval(Buffer.from('"+encoded+"','base64').toString('utf8'))")


@unittest.skipUnless(os.name=='nt' and shutil.which('node'),'Windows guaranteed-tree current-workspace profile required')
class CurrentWorkspaceVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.project=self.root/'project';self.project.mkdir()
        self.cache=self.root/'cache';self.cache.mkdir()
        self.env=patch.dict(os.environ,{'GIT_CEILING_DIRECTORIES':str(self.root),
            'NODE_OPTIONS':'','NODE_PATH':''});self.env.start();self.addCleanup(self.env.stop)
        manifest={'name':'current-workspace-regression','version':'1.0.0','private':True}
        lock={'name':manifest['name'],'version':'1.0.0','lockfileVersion':2,
            'requires':True,'packages':{'':{'name':manifest['name'],'version':'1.0.0'}}}
        (self.project/'package.json').write_text(json.dumps(manifest))
        raw=json.dumps(lock).encode();(self.project/'package-lock.json').write_bytes(raw)
        (self.project/'marker.txt').write_text('original')
        self.plan=compile_npm_dependency_obligations(raw,raw,exact_targets={},changed_instances=[],
            immutable_packages=[],excluded_packages=[],delta_digest='a'*64,scope_digest='b'*64)
        self.key=source_snapshot_fingerprint(self.project)

    def invoke(self,body,**options):
        return verify_current_workspace(self.project,expected_source_key=options.get('key',self.key),
            dependency_plan=self.plan,commands=[command(body)],cache_dir=self.cache,final_profile_digest='c'*64,
            deadline=options.get('deadline',time.time()+60),materialize=True)

    def test_fresh_command_runs_in_actual_workspace_and_closes_capture(self):
        import source_snapshot
        with patch.object(source_snapshot, "build_source_tree_manifest",
                          wraps=source_snapshot.build_source_tree_manifest) as scans:
            value=self.invoke("console.log(process.cwd());")
        self.assertFalse(any(call.kwargs.get("progress_label") == "hot SourceSnapshot live-source continuity"
                             for call in scans.call_args_list))
        self.assertNotIn(source_snapshot._active_key(self.project), source_snapshot._LIVE_SOURCE_WATCHERS)
        row=value['commandObservations'][0]
        expected=hashlib.sha256((str(self.project.resolve())+'\n').encode()).hexdigest()
        self.assertEqual(row['stdoutDigest'],expected)
        self.assertEqual(row['origin'],'EXECUTED_FRESH')
        self.assertEqual(value['installation']['supervision'],'guaranteed-tree')
        self.assertEqual([row['operation'] for row in value['ownerOperationObservations']],
            ['strict-frozen-install','project-command'])
        self.assertEqual([row['commandIndex'] for row in value['ownerOperationObservations']],[None,1])
        self.assertTrue(all(row['supervision']=='guaranteed-tree' and row['descendantsRemaining']==0 for row in value['ownerOperationObservations']))
        self.assertTrue(value['sourceSnapshotCleanupClosed'])
        self.assertFalse(value['currentWorkspaceVerified'])
        self.assertFalse(value['checkpointPublished'])
        self.assertFalse(value['fullAcceptance'])
        self.assertEqual((self.project/'marker.txt').read_text(),'original')

    def test_real_nonzero_command_cannot_return_observation(self):
        with self.assertRaisesRegex(MaterializedWorkspaceVerificationError,'COMMAND_FAILED'):
            self.invoke('process.exit(7);')

    def test_failed_command_private_tail_is_bounded_and_not_public(self):
        import traceback
        with self.assertRaises(MaterializedWorkspaceVerificationError) as caught:
            self.invoke("process.stdout.write('x'.repeat(16000)+'PRIVATE_LAST_COMMAND');process.exit(7);")
        error=caught.exception;private=error._private_failed_command_diagnostic
        self.assertEqual(private['commandIndex'],1);self.assertEqual(private['returnCode'],7)
        self.assertEqual(len(private['stdoutTail'].encode()),8192)
        self.assertTrue(private['stdoutTail'].endswith('PRIVATE_LAST_COMMAND'))
        self.assertNotIn('PRIVATE_LAST_COMMAND',str(error));self.assertNotIn('PRIVATE_LAST_COMMAND',repr(error))
        self.assertNotIn('PRIVATE_LAST_COMMAND',json.dumps(error.operation_observations))
        self.assertNotIn('PRIVATE_LAST_COMMAND',''.join(traceback.format_exception_only(type(error),error)))
        self.assertEqual(error.operation_observations[-1]['returnCode'],7)

    def test_failure_diagnostic_preserves_source_guard_precedence(self):
        with self.assertRaisesRegex(MaterializedWorkspaceVerificationError,'INPUT_CHANGED') as caught:
            self.invoke("console.log('PRIVATE_FAILURE');require('fs').writeFileSync('marker.txt','changed');process.exit(9);")
        self.assertEqual(caught.exception._private_failed_command_diagnostic['returnCode'],9)
        self.assertEqual(caught.exception._private_failed_command_diagnostic['commandIndex'],1)

    def test_actual_source_write_is_not_accepted_as_a_check(self):
        with self.assertRaisesRegex(MaterializedWorkspaceVerificationError,'INPUT_CHANGED'):
            self.invoke("require('node:fs').writeFileSync('marker.txt','changed');")
        self.assertEqual((self.project/'marker.txt').read_text(),'changed')

    def test_empty_auxiliary_directory_observed_separately_from_graph(self):
        value=self.invoke("require('node:fs').mkdirSync('node_modules/.generated-empty',{recursive:true});")
        self.assertEqual(value['materializedDependencyObligations']['instanceCount'],0)
        self.assertEqual(value['materializedDependencyObligations']['unknownCount'],0)
        last=value['auxiliaryDirectoryObservations'][-1]
        self.assertEqual(last['directories'][0]['relativePath'],'node_modules/.generated-empty')
        self.assertFalse(last['arbitraryFilesystemSemanticsVerified'])
    def test_empty_auxiliary_directory_cannot_hide_nonzero_check(self):
        with self.assertRaisesRegex(MaterializedWorkspaceVerificationError,'COMMAND_FAILED'):
            self.invoke("require('node:fs').mkdirSync('node_modules/.generated-empty',{recursive:true});process.exit(7);")
    def test_generated_dist_is_not_implicitly_excluded(self):
        with self.assertRaisesRegex(MaterializedWorkspaceVerificationError,'INPUT_CHANGED'):
            self.invoke("require('node:fs').mkdirSync('dist');require('node:fs').writeFileSync('dist/result.js','changed');")

    def test_missing_tree_backend_refuses_before_install(self):
        with patch("materialized_workspace_verifier.has_guaranteed_tree_backend", return_value=False), \
             patch("materialized_workspace_verifier.run_supervised") as runner:
            with self.assertRaisesRegex(MaterializedWorkspaceVerificationError, "PROCESS_CLOSURE_UNAVAILABLE") as caught:
                self.invoke("process.exit(0);")
        runner.assert_not_called()
        self.assertEqual(caught.exception.operation_observations, ())
        self.assertFalse((self.project / "node_modules").exists())

    def test_stale_source_stops_before_install(self):
        with self.assertRaisesRegex(MaterializedWorkspaceVerificationError,'SOURCE_MISMATCH'):
            self.invoke('process.exit(0);',key='0'*32)
        self.assertFalse((self.project/'node_modules').exists())

    def test_expired_attempt_is_not_given_a_new_budget(self):
        with self.assertRaisesRegex(MaterializedWorkspaceVerificationError,'DEADLINE_EXCEEDED'):
            self.invoke('process.exit(0);',deadline=time.time()-1)
        self.assertFalse((self.project/'node_modules').exists())

    def test_existing_dependency_tree_is_preserved_without_implicit_install(self):
        bin_dir=self.project/'node_modules/.bin';bin_dir.mkdir(parents=True)
        sentinel=bin_dir/'existing-user-entry';sentinel.write_text('preserve me')
        value=verify_current_workspace(self.project,expected_source_key=self.key,
            dependency_plan=self.plan,commands=[command('console.log(process.cwd());')],
            cache_dir=self.cache,final_profile_digest='c'*64,deadline=time.time()+60)
        self.assertEqual(value['installation']['status'],'EXISTING_TREE_PHYSICALLY_OBSERVED')
        self.assertEqual([row['operation'] for row in value['ownerOperationObservations']],['project-command'])
        self.assertEqual(sentinel.read_text(),'preserve me')

    def test_cold_install_does_not_destroy_existing_dependency_tree(self):
        existing=self.project/'node_modules/local-state';existing.mkdir(parents=True)
        file=existing/'do-not-delete';file.write_text('unrelated')
        with self.assertRaisesRegex(MaterializedWorkspaceVerificationError,'REQUIRES_RECOVERABLE_STAGING'):
            self.invoke('process.exit(0);')
        self.assertEqual(file.read_text(),'unrelated')
