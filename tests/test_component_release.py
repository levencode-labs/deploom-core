"""Real Git/filesystem release recovery; fake network only, no publication."""
import base64
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import component_release as release
import release_ci as ci

class ReleaseStateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.call('init','-b','main');self.call('config','user.name','Release Fixture');self.call('config','user.email','fixture@example.invalid');self.call('config','commit.gpgSign','false');self.call('config','tag.gpgSign','false');self.call('config','core.autocrlf','false')
        self.original=b'[project]\r\nname = "deploom-core"\r\nversion = "0.1.1"\r\ndescription = "preserve"\r\n'
        (self.root/'pyproject.toml').write_bytes(self.original);(self.root/'.gitignore').write_text('.component-release/\n__pycache__/\n');(self.root/'README.md').write_text('public overview\n');self.call('add','.');self.call('commit','-m','source')
        self.base=self.call('rev-parse','HEAD');self.call('update-ref','refs/remotes/origin/main',self.base);self.call('remote','add','origin','git@github.com:levencode-labs/deploom-core.git')
    def call(self,*args):
        r=subprocess.run(['git','-C',str(self.root),*args],capture_output=True,text=True,timeout=15)
        if r.returncode:raise RuntimeError('fixture Git failed: '+str(args))
        return r.stdout.strip()
    def test_version_bytes_and_readme_survive_same_attempt_recovery(self):
        state=release.prepare(self.root);before,after=release.changes(self.root,state)['pyproject.toml']
        self.assertEqual(before,self.original);self.assertIn(b'\r\nversion = "0.1.2"\r\n',after)
        release.atomic(self.root/'pyproject.toml',after)  # interrupted before version commit
        resumed=release.prepare(self.root);self.assertEqual(resumed['tag'],'v0.1.2')
        commit=release.commit_version(self.root,resumed)
        again=release.prepare(self.root,tag='v0.1.2');self.assertEqual(release.commit_version(self.root,again),commit)
        self.assertEqual(self.call('rev-list','--count','HEAD'), '2')
        self.assertEqual((self.root/'README.md').read_text(),'public overview\n')
        self.assertEqual((self.root/'pyproject.toml').read_bytes(),after)
    def test_unrelated_work_prevents_mutation_or_staging(self):
        state=release.prepare(self.root);(self.root/'README.md').write_text('user edit')
        with self.assertRaisesRegex(release.ReleaseError,'UNRELATED_CHANGES'):release.commit_version(self.root,state)
        self.assertEqual((self.root/'pyproject.toml').read_bytes(),self.original)
        self.assertEqual(self.call('diff','--cached','--name-only'),'')
    def test_interrupted_atomic_file_replace_resumes_without_another_version(self):
        state=release.prepare(self.root)
        with patch.object(release.os,'replace',side_effect=OSError('simulated interruption')):
            with self.assertRaisesRegex(OSError,'simulated interruption'):release.commit_version(self.root,state)
        self.assertEqual(release.dirty_paths(self.root),set())
        resumed=release.prepare(self.root);release.commit_version(self.root,resumed)
        self.assertEqual(release.package(self.root),('deploom-core','0.1.2'))
        self.assertEqual(self.call('rev-list','--count','HEAD'),'2')
    def test_changed_version_file_is_preserved(self):
        state=release.prepare(self.root);changed=self.original+b'# concurrent edit\r\n';(self.root/'pyproject.toml').write_bytes(changed)
        with self.assertRaisesRegex(release.ReleaseError,'VERSION_FILE_CHANGED'):release.commit_version(self.root,state)
        self.assertEqual((self.root/'pyproject.toml').read_bytes(),changed)
    def test_wrong_branch_origin_and_unmerged_head_fail_before_version_edit(self):
        self.call('switch','-c','feature')
        with self.assertRaisesRegex(release.ReleaseError,'REQUIRES_MAIN'):release.prepare(self.root)
        self.call('switch','main');self.call('remote','set-url','origin','git@github.com:example/other.git')
        with self.assertRaisesRegex(release.ReleaseError,'SSH_ORIGIN'):release.prepare(self.root)
        self.call('remote','set-url','origin','git@github.com:levencode-labs/deploom-core.git');(self.root/'README.md').write_text('new source');self.call('add','README.md');self.call('commit','-m','unmerged source')
        with self.assertRaisesRegex(release.ReleaseError,'NOT_SYNCED'):release.prepare(self.root)
        self.assertEqual((self.root/'pyproject.toml').read_bytes(),self.original)
    def test_atomic_push_and_retry_never_bump_or_force_existing_tag(self):
        state=release.prepare(self.root);commit=release.commit_version(self.root,state);original=release.git;calls=[];remote={'main':self.base,'tag':None}
        def transport(root,*args,check=True):
            calls.append(args)
            if args[0]=='fetch':return ''
            if args==('rev-parse','FETCH_HEAD'):return remote['main']
            if args[0]=='ls-remote':
                return '' if remote['tag'] is None else ('' if '--tags' in args else remote['main']+'\trefs/heads/main\n')+original(root,'rev-parse','refs/tags/v0.1.2')+'\trefs/tags/v0.1.2\n'+remote['tag']+'\trefs/tags/v0.1.2^{}'
            if args[0]=='push':
                self.assertIn('--atomic',args);self.assertNotIn('--force',args);remote.update(main=commit,tag=commit);return ''
            return original(root,*args,check=check)
        with patch.object(release,'git',side_effect=transport):
            self.assertEqual(release.push_release(self.root,state)['status'],'PUSHED_AWAITING_WORKFLOW')
            resumed=release.prepare(self.root);release.push_release(self.root,resumed)
        self.assertEqual(sum(c[0]=='push' for c in calls),1);self.assertEqual(self.call('rev-list','--count','HEAD'),'2')
    def test_process_lock_prevents_concurrent_launcher_and_releases_after_exit(self):
        with release.release_lock(self.root):
            with self.assertRaisesRegex(release.ReleaseError,'ANOTHER_RELEASE_PROCESS'):
                with release.release_lock(self.root):self.fail('concurrent owner entered')
        with release.release_lock(self.root):pass
    def test_tampered_state_cannot_inject_nonversion_source_changes(self):
        state=release.prepare(self.root);row=state['files']['pyproject.toml']
        before=self.original.replace(b'preserve',b'injected');after=before.replace(b'0.1.1',b'0.1.2')
        row.update(before=base64.b64encode(before).decode(),after=base64.b64encode(after).decode(),beforeSha256=release.digest(before),afterSha256=release.digest(after))
        with self.assertRaisesRegex(release.ReleaseError,'DIFFERS_FROM_SOURCE'):release.commit_version(self.root,state)
        self.assertEqual((self.root/'pyproject.toml').read_bytes(),self.original)
    def test_immutable_remote_tag_conflict_never_pushes(self):
        state=release.prepare(self.root);release.commit_version(self.root,state);original=release.git;push=[]
        def transport(root,*args,check=True):
            if args[0]=='fetch':return ''
            if args==('rev-parse','FETCH_HEAD'):return self.base
            if args[0]=='ls-remote':return self.base+'\trefs/tags/v0.1.2^{}'
            if args[0]=='push':push.append(args);self.fail('must not push a conflicting release')
            return original(root,*args,check=check)
        with patch.object(release,'git',side_effect=transport),self.assertRaisesRegex(release.ReleaseError,'REMOTE_TAG_CONFLICT'):release.push_release(self.root,state)
        self.assertEqual(push,[])

class ExactWorkflowIdentityTests(unittest.TestCase):
    def test_definition_on_moving_main_cannot_release_another_tag_commit(self):
        with patch.object(ci,'package',return_value=('deploom-core','0.1.2')),patch.object(ci,'git',return_value='a'*40),patch.dict(os.environ,{'GITHUB_REPOSITORY':'levencode-labs/deploom-core','GITHUB_SHA':'b'*40}):
            with self.assertRaisesRegex(release.ReleaseError,'DEFINITION_NOT_FROM_TAG'):ci.identity('v0.1.2')
    def test_publisher_refuses_missing_qualified_bundle_before_any_api(self):
        value={'repository':'levencode-labs/deploom-core','package':'deploom-core','version':'0.1.2','tag':'v0.1.2','commit':'a'*40,'tagObject':'c'*40}
        with patch.object(ci,'identity',return_value=value),patch.object(ci,'api') as api,patch.dict(os.environ,{'EXPECTED_MANIFEST_SHA256':'','RELEASE_ARTIFACT_ID':'','RELEASE_ARTIFACT_DIGEST':''}):
            with self.assertRaisesRegex(release.ReleaseError,'BUNDLE_IDENTITY_MISSING'):ci.publish('v0.1.2',ROOT)
        api.assert_not_called()

class DraftReleaseLookupTests(unittest.TestCase):
    def test_existing_draft_is_found_without_tag_endpoint(self):
        draft={'id':432459869,'tag_name':'v0.1.2','draft':True,'assets':[]}
        with patch.object(ci,'api',return_value=[draft]) as request:
            self.assertEqual(ci.find_release('levencode-labs/deploom-core','v0.1.2'),draft)
        request.assert_called_once_with('repos/levencode-labs/deploom-core/releases?per_page=100&page=1')
    def test_pagination_absence_duplicate_and_api_failure_fail_closed(self):
        first=[{'tag_name':'other'}]*100;draft={'id':1,'tag_name':'v0.1.2','draft':True}
        with patch.object(ci,'api',side_effect=[first,[draft]]):self.assertEqual(ci.find_release('levencode-labs/deploom-core','v0.1.2'),draft)
        with patch.object(ci,'api',return_value=[]):self.assertIsNone(ci.find_release('levencode-labs/deploom-core','v0.1.2'))
        with patch.object(ci,'api',return_value=[draft,draft]),self.assertRaisesRegex(release.ReleaseError,'DUPLICATE'):ci.find_release('levencode-labs/deploom-core','v0.1.2')
        with patch.object(ci,'api',side_effect=release.ReleaseError('denied')),self.assertRaisesRegex(release.ReleaseError,'denied'):ci.find_release('levencode-labs/deploom-core','v0.1.2')

class ImmutableAssetTests(unittest.TestCase):
    def test_missing_assets_can_resume_but_different_or_unknown_assets_cannot(self):
        expected={'package.whl':{'size':5,'digest':'sha256:'+'a'*64},'SHA256SUMS.txt':{'size':7,'digest':'sha256:'+'b'*64}}
        row={'name':'package.whl','size':5,'digest':'sha256:'+'a'*64,'state':'uploaded'}
        self.assertEqual(ci.reconcile_assets([row],expected),['SHA256SUMS.txt'])
        for rows in ([{**row,'digest':'sha256:'+'c'*64}],[row,row],[{**row,'name':'foreign'}]):
            with self.subTest(rows=rows),self.assertRaises(release.ReleaseError):ci.reconcile_assets(rows,expected)
    def test_source_identity_and_checksum_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            folder=Path(raw);value={'repository':'levencode-labs/deploom-core','package':'deploom-core','version':'0.1.2','tag':'v0.1.2','commit':'a'*40,'tagObject':'c'*40}
            for name in ['deploom_core-0.1.2-py3-none-any.whl','deploom_core-0.1.2.tar.gz']:(folder/name).write_bytes(b'fixture bytes, not a built distribution')
            (folder/'RELEASE-EVIDENCE.json').write_text(json.dumps(value))
            (folder/'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(folder.iterdir())))
            ci.expected_assets(folder,value)
            (folder/'deploom_core-0.1.2.tar.gz').write_bytes(b'changed')
            with self.assertRaisesRegex(release.ReleaseError,'ARTIFACT_CHANGED'):ci.expected_assets(folder,value)
            with self.assertRaisesRegex(release.ReleaseError,'SOURCE_MISMATCH'):ci.expected_assets(folder,{**value,'commit':'b'*40})
class McpVersionSynchronizationTests(unittest.TestCase):
    @unittest.skipUnless((ROOT/'scripts/update_release_manifest.py').is_file(),'MCP-only canonical manifest owner')
    def test_actual_canonical_owner_accepts_all_three_version_files_and_same_pin(self):
        f=ReleaseStateTests();f.setUp();self.addCleanup(f.doCleanups);root=f.root
        p=root/'pyproject.toml';p.write_bytes(f.original.replace(b'deploom-core',b'deploom-mcp'))
        (root/'src/deploom_mcp').mkdir(parents=True);(root/'src/deploom_mcp/__init__.py').write_text('__version__ = "0.1.1"\n')
        (root/'scripts').mkdir();(root/'scripts/update_release_manifest.py').write_bytes((ROOT/'scripts/update_release_manifest.py').read_bytes());(root/'build_support.py').write_bytes((ROOT/'build_support.py').read_bytes())
        (root/'contracts').mkdir();(root/'contracts/upgrade-blueprint.schema.json').write_text('{}')
        (root/'skills/deploom-upgrade').mkdir(parents=True);(root/'skills/deploom-upgrade/contract.json').write_text(json.dumps({'contractVersion':'fixture','bundleSha256':'a'*64}))
        core=root/'upstream/deploom';core.mkdir(parents=True)
        for args in [('init','-b','main'),('config','user.name','Release Fixture'),('config','user.email','fixture@example.invalid'),('config','commit.gpgSign','false')]:
            subprocess.run(['git','-C',str(core),*args],check=True,capture_output=True,timeout=15)
        (core/'VERSION').write_text('engine-fixture');(core/'fixture.py').write_text('VALUE=1\n')
        subprocess.run(['git','-C',str(core),'add','.'],check=True,capture_output=True,timeout=15);subprocess.run(['git','-C',str(core),'commit','-m','fixture core'],check=True,capture_output=True,timeout=15)
        (root/'.gitmodules').write_text('[submodule "upstream/deploom"]\n path = upstream/deploom\n url = git@github.com:levencode-labs/deploom-core.git\n')
        f.call('add','.');f.call('remote','set-url','origin','git@github.com:levencode-labs/deploom-mcp.git')
        subprocess.run([sys.executable,'-B','scripts/update_release_manifest.py'],cwd=root,check=True,capture_output=True,timeout=30)
        f.call('add','.');f.call('commit','-m','MCP fixture');f.call('update-ref','refs/remotes/origin/main',f.call('rev-parse','HEAD'))
        pin=json.loads((root/'release-manifest.json').read_bytes())['core']['revision']
        state=release.prepare(root);release.commit_version(root,state)
        self.assertEqual(release.package(root),('deploom-mcp','0.1.2'))
        self.assertEqual((root/'src/deploom_mcp/__init__.py').read_text(),'__version__ = "0.1.2"\n')
        manifest=json.loads((root/'release-manifest.json').read_bytes());self.assertEqual(manifest['mcpVersion'],'0.1.2');self.assertEqual(manifest['core']['revision'],pin)
        self.assertEqual((core/'VERSION').read_text(),'engine-fixture')

if __name__=='__main__':unittest.main()
