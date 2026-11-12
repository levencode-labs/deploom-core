import unittest,json,shutil,os
from pathlib import Path
from semantic_version import NpmSpec,Version
from project_runtime import normalize_npm_range,node_range_satisfied
from verification_process_supervisor import run_supervised
class NpmRangeNormalizationTests(unittest.TestCase):
 def test_official_installed_npm_semver_crosscheck(self):
  cases=[['>= 3.1.0 < 4','3.1.0'],['>= 3.1.0 < 4','3.9.1'],['>= 3.1.0 < 4','4.0.0'],['^ 1.2.3','1.5.0'],['^ 1.2.3','2.0.0'],['~ 1.2.3','1.2.4'],['~ 1.2.3','1.3.0'],['1.2.3 - 2.0.0','2.0.0'],['>= 1.0.0 || < 0.1.0','0.0.9'],['>= 1.0.0-beta.1 < 2','1.0.0-beta.2'],
         ['>= v0.10.32','22.17.1'],['>=v14','22.17.1'],['>=v14','12.0.0'],
         ['>= v22.0.0 < v23','23.0.0'],['^v22.0.0','22.17.1']]
  from draft_npm_preflight import _npm_command
  node,npm=_npm_command();semver=Path(npm).resolve().parent.parent/'node_modules/semver';body="const s=require(process.argv[1]);const c=JSON.parse(process.argv[2]);console.log(JSON.stringify(c.map(([r,v])=>s.satisfies(v,r))))"
  result=run_supervised([str(node),'-e',body,str(semver),json.dumps(cases)],Path.cwd(),timeout_seconds=10,max_output_bytes=4096)
  self.assertEqual(result.returncode,0);self.assertEqual(result.supervision.quality,'guaranteed-tree' if os.name=='nt' else 'best-effort');self.assertEqual(result.supervision.descendants_remaining,0)
  native=json.loads(result.stdout)
  for (spec,version),expected in zip(cases,native):
   with self.subTest(spec=spec,version=version):self.assertEqual(NpmSpec(normalize_npm_range(spec)).match(Version(version)),expected);self.assertEqual(node_range_satisfied(spec,version),expected)
 def test_malformed_range_not_repaired_into_success(self):
  for bad in ['>= nonsense','npm:foreign@^1','>= > 2','>=V14','v 22']:
   with self.subTest(bad=bad),self.assertRaises(ValueError):NpmSpec(normalize_npm_range(bad))
  with self.assertRaises(ValueError):normalize_npm_range(None)
if __name__=='__main__':unittest.main()
