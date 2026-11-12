import unittest,tempfile,json,hashlib,tarfile,io,base64,copy
import os
from pathlib import Path
from npm_platform_obligations import observe_node_host,verify_platform_absence,NpmPlatformEvidenceError
from resolved_dependency_state import compile_npm_dependency_obligations,observe_npm_dependency_obligations,MaterializedDependencyObligationError
@unittest.skipUnless(os.name=='nt','Platform archive evidence is currently Windows-only')
class PlatformAbsenceTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.host=observe_node_host()
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name);self.archive=self.root/'foreign.tgz'
  self.manifest={'name':'foreign','version':'1.0.0','os':['linux'],'cpu':['arm64'],'libc':['glibc']};self.make_archive()
  self.lock={'lockfileVersion':3,'packages':{'':{'dependencies':{'held':'1.0.0'}},'node_modules/held':{'version':'1.0.0','optionalDependencies':{'foreign':'^1.0.0'},'peerDependencies':{'absent-peer':'^1.0.0'},'peerDependenciesMeta':{'absent-peer':{'optional':True}}},'node_modules/foreign':{'version':'1.0.0','optional':True,'os':['linux'],'cpu':['arm64'],'integrity':self.sri,'resolved':'https://registry.npmjs.org/foreign/-/foreign-1.0.0.tgz'}}}
  self.rules={'schemaVersion':1,'kind':'NPM_V3_SRI_PLATFORM_ABSENCE_V1','host':self.host,'artifacts':[{'instance':'node_modules/foreign','archivePath':str(self.archive.resolve())}]}
 def make_archive(self, root='package', extra_root=None):
  raw=json.dumps(self.manifest).encode()
  with tarfile.open(self.archive,'w:gz') as tf:
   entry=tarfile.TarInfo(f'{root}/package.json');entry.size=len(raw);tf.addfile(entry,io.BytesIO(raw))
   if extra_root is not None:
    extra=tarfile.TarInfo(f'{extra_root}/README');extra.size=1;tf.addfile(extra,io.BytesIO(b'x'))
  self.sri='sha512-'+base64.b64encode(hashlib.sha512(self.archive.read_bytes()).digest()).decode()
 def compile(self):
  raw=json.dumps(self.lock).encode();return compile_npm_dependency_obligations(raw,raw,exact_targets={},changed_instances=[],delta_digest='a'*64,scope_digest='b'*64,optional_absence_rules=self.rules)
 def observe(self,plan):return observe_npm_dependency_obligations(self.root,plan,source_origin_digest='c'*64,resolved_state_key='d'*64)
 def physical(self):
  (self.root/'package-lock.json').write_text(json.dumps(self.lock));(self.root/'package.json').write_text(json.dumps(self.lock['packages']['']))
  path=self.root/'node_modules/held';path.mkdir(parents=True);(path/'package.json').write_text(json.dumps({'name':'held',**self.lock['packages']['node_modules/held']}))
 def test_real_archive_enriches_missing_libc_preserves_full_denominator(self):
  plan=self.compile();self.physical();r=self.observe(plan);self.assertEqual(r['instanceCount'],2);self.assertEqual(r['observedInstanceCount'],1);self.assertEqual(r['platformInapplicableInstanceCount'],1);self.assertEqual(r['unknownCount'],0);self.assertFalse(r['fullAcceptance']);self.assertEqual(r['platformInapplicableInstances'][0]['platformMetadata']['libc'],['glibc'])
 def test_archive_with_a_single_package_named_root_is_supported(self):
  self.make_archive('foreign v1.0')
  self.lock['packages']['node_modules/foreign']['integrity']=self.sri
  plan=self.compile()
  self.physical()
  self.assertEqual(self.observe(plan)['platformInapplicableInstanceCount'],1)

 def test_archive_with_multiple_top_level_roots_is_rejected(self):
  self.make_archive('foreign',extra_root='other')
  self.lock['packages']['node_modules/foreign']['integrity']=self.sri
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'ARCHIVE_ROOT_UNPROVEN'):self.compile()

 def test_multiple_omissions_resolve_each_incoming_declaration_once(self):
  from unittest.mock import patch
  import npm_platform_obligations as platform
  self.archive=self.root/'foreign2.tgz'
  self.manifest={**self.manifest,'name':'foreign2'}
  self.make_archive()
  self.lock['packages']['node_modules/foreign2']={
      **self.lock['packages']['node_modules/foreign'],
      'integrity':self.sri,'resolved':'https://registry.npmjs.org/foreign2/-/foreign2-1.0.0.tgz',
  }
  self.lock['packages']['node_modules/held']['optionalDependencies']['foreign2']='^1.0.0'
  self.rules['artifacts'].append({'instance':'node_modules/foreign2','archivePath':str(self.archive.resolve())})
  with patch.object(platform,'_resolve',wraps=platform._resolve) as resolve:
   proof=verify_platform_absence(self.lock,self.rules)
  self.assertEqual(set(proof),{'node_modules/foreign','node_modules/foreign2'})
  self.assertEqual(resolve.call_count,4)

 def test_mutating_lock_os_cannot_self_authorize_absence(self):
  self.lock['packages']['node_modules/foreign']['os']=['darwin']
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'PLATFORM_MISMATCH'):self.compile()
 def test_applicable_archive_is_not_omittable(self):
  self.manifest['os']=['win32'];self.manifest['cpu']=[self.host['arch']];self.make_archive();self.lock['packages']['node_modules/foreign'].update(os=self.manifest['os'],cpu=self.manifest['cpu'],integrity=self.sri)
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'HOST_APPLICABLE'):self.compile()
 def test_required_edge_or_orphan_rejected(self):
  row=self.lock['packages']['node_modules/held'];row['dependencies']={'foreign':'^1.0.0'};del row['optionalDependencies']
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'REQUIRED_INCOMING'):self.compile()
  del row['dependencies']
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'ORPHAN'):self.compile()
 def test_bad_sri_and_changed_host_and_invalid_boolean(self):
  for mutation in ['sri','host','optional']:
   old=copy.deepcopy((self.lock,self.rules))
   if mutation=='sri':self.lock['packages']['node_modules/foreign']['integrity']='sha512-foreign'
   elif mutation=='host':self.rules['host']={**self.host,'nodeSha256':'0'*64}
   else:self.lock['packages']['node_modules/foreign']['optional']=1
   with self.subTest(mutation=mutation),self.assertRaises(MaterializedDependencyObligationError):self.compile()
   self.lock,self.rules=old
 def test_default_v3_and_v2_do_not_gain_omission_permission(self):
  raw=json.dumps(self.lock).encode();plan=compile_npm_dependency_obligations(raw,raw,exact_targets={},changed_instances=[],delta_digest='a'*64,scope_digest='b'*64);self.physical()
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'INSTANCE_SET_MISMATCH'):self.observe(plan)
  self.lock['lockfileVersion']=2
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'LOCK_UNSUPPORTED'):self.compile()
 def test_missing_required_peer_and_present_bad_optional_peer_rejected(self):
  self.lock['packages']['node_modules/held']['peerDependenciesMeta']={'absent-peer':{'optional':False}};plan=self.compile();self.physical()
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'EDGE_MISSING'):self.observe(plan)
  self.lock['packages']['node_modules/held']['peerDependenciesMeta']={'absent-peer':{'optional':True}}
  self.lock['packages']['node_modules/absent-peer']={'version':'2.0.0'};plan=self.compile();(self.root/'package-lock.json').write_text(json.dumps(self.lock));(self.root/'node_modules/held/package.json').write_text(json.dumps({'name':'held',**self.lock['packages']['node_modules/held']}));p=self.root/'node_modules/absent-peer';p.mkdir();(p/'package.json').write_text('{"name":"absent-peer","version":"2.0.0"}')
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'EDGE_MISMATCH'):self.observe(plan)
 def test_unexpected_presence_and_archive_drift_rejected(self):
  plan=self.compile();self.physical();p=self.root/'node_modules/foreign';p.mkdir();(p/'package.json').write_text(json.dumps(self.manifest))
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'INSTANCE_SET_MISMATCH'):self.observe(plan)
  (p/'package.json').unlink();p.rmdir();self.archive.write_bytes(b'changed')
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'SRI_MISMATCH'):self.observe(plan)
 def test_negative_nonmatching_selector_does_not_authorize_absence(self):
  for selectors in [['!linux'],['win32','!win32'],['any','linux']]:
   self.manifest.update(os=selectors,cpu=[self.host['arch']]);self.make_archive();self.lock['packages']['node_modules/foreign'].update(os=selectors,cpu=[self.host['arch']],integrity=self.sri)
   with self.subTest(selectors=selectors),self.assertRaises(MaterializedDependencyObligationError):self.compile()
 def test_absent_platform_declarations_do_not_prove_inapplicable(self):
  self.manifest.pop('os');self.manifest.pop('cpu');self.make_archive();row=self.lock['packages']['node_modules/foreign'];row.pop('os');row.pop('cpu');row['integrity']=self.sri
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'HOST_APPLICABLE'):self.compile()
 def test_valid_comparator_whitespace_preserves_optional_range(self):
  self.lock['packages']['node_modules/held']['optionalDependencies']['foreign']='>= 1.0.0 < 2'
  plan=self.compile();self.physical();self.assertEqual(self.observe(plan)['instanceCount'],2)
 def test_negative_platform_selectors(self):
  self.manifest.update(os=['!win32'],cpu=[self.host['arch']]);self.make_archive();self.lock['packages']['node_modules/foreign'].update(os=['!win32'],cpu=[self.host['arch']],integrity=self.sri);self.compile()
 def test_explicit_total_archive_budget_is_bounded_and_bound_in_plan(self):
  from npm_platform_obligations import total_archive_budget
  self.assertEqual(total_archive_budget(self.rules),128*1024*1024)
  self.rules['resourceLimits']={'maxTotalArchiveBytes':256*1024*1024}
  self.assertEqual(total_archive_budget(self.rules),256*1024*1024)
  self.assertEqual(self.compile()['optionalAbsenceRules']['resourceLimits'],self.rules['resourceLimits'])
 def test_resource_limit_boolean_null_unknown_or_excessive_rejected(self):
  from npm_platform_obligations import validate_rules_shape
  for limit in [None,{},True,{'maxTotalArchiveBytes':True},{'maxTotalArchiveBytes':128*1024*1024-1},{'maxTotalArchiveBytes':256*1024*1024+1},{'maxTotalArchiveBytes':256*1024*1024,'skipSRI':True}]:
   self.rules['resourceLimits']=limit
   with self.subTest(limit=limit),self.assertRaisesRegex(NpmPlatformEvidenceError,'RESOURCE_LIMIT_SCHEMA'):validate_rules_shape(self.rules)
 def test_aggregate_archive_budget_boundary_remains_fail_closed(self):
  from unittest.mock import patch
  size=self.archive.stat().st_size
  # Reduce the budget only at this unit cutpoint; actual archive/SRI are real.
  with patch('npm_platform_obligations.total_archive_budget',return_value=size-1):
   with self.assertRaisesRegex(MaterializedDependencyObligationError,'TOTAL_ARCHIVE_LIMIT'):self.compile()
  with patch('npm_platform_obligations.total_archive_budget',return_value=size):self.compile()
if __name__=='__main__':unittest.main()
