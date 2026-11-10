import unittest
from workspace_peer_model import declaration_id, plan_workspace_from_registry, prepare_workspace_from_registry

KEY = ('.', 'dependencies', 'demo')

class Registry:
    def fetch_npm_metadata(self, name):
        return {'versions': {v: {'name': name, 'version': v} for v in (
            '1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0', '2.0.0', '2.1.0-beta.1')}}
    def registry_tarball_url(self, metadata, version):
        return version
    def registry_artifact_url_allowed(self, url):
        return True

class BoundedSelectionTests(unittest.TestCase):
    def plan(self, **kwargs):
        return plan_workspace_from_registry({'node_modules/demo': {'version': '1.0.0'}},
            {KEY: '^1'}, {KEY: (1,)}, {}, Registry(), **kwargs)

    def test_latest_stable_plus_baseline_bound_and_proof_scope(self):
        result = self.plan(bounded_selection=True, candidate_limit=3)
        self.assertEqual(result['selectedCandidates'][0]['versions'], ['1.4.0', '1.3.0', '1.0.0'])
        self.assertEqual(result['candidateSelection'], {'rule': 'LATEST_STABLE_PLUS_BASELINE_V1',
            'limit': 3, 'truncated': True, 'proofScope': 'SELECTED_DOMAIN_ONLY'})
        self.assertEqual(result['domain']['selection'], 'SERVER_BOUNDED')
        self.assertEqual(result['assignment'][declaration_id(KEY)], '1.0.0')

    def test_explicit_legacy_domain_is_not_silently_truncated(self):
        result = self.plan(candidate_limit=3)
        self.assertEqual(result['status'], 'UNKNOWN')
        with self.assertRaisesRegex(ValueError, 'SELECTION_CONFLICT'):
            self.plan(candidate_versions={KEY: ('1.0.0',)}, bounded_selection=True)

    def test_exact_target_and_unknown_evidence_are_not_dropped(self):
        registry = Registry()
        registry.registry_artifact_url_allowed = lambda _: False
        result = plan_workspace_from_registry({'node_modules/demo': {'version': '1.0.0'}},
            {KEY: '^1'}, {KEY: (2,)}, {KEY: '2.0.0'}, registry, bounded_selection=True, candidate_limit=1)
        self.assertEqual(result['selectedCandidates'][0]['versions'], ['2.0.0'])
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(result['domain']['evidenceCoverage'], 'PARTIAL')

    def test_prepared_snapshot_retains_selected_versions_and_no_global_optimum(self):
        prepared = prepare_workspace_from_registry({'node_modules/demo': {'version': '1.0.0'}},
            {KEY: '^1'}, {KEY: (1,)}, {}, Registry(), bounded_selection=True, candidate_limit=2)
        first = prepared.solve()
        second = prepared.solve((first['assignment'],))
        self.assertEqual(first['selectedCandidates'], second['selectedCandidates'])
        self.assertNotEqual(first['assignment'], second['assignment'])
        self.assertEqual(second['optimality'], 'PROVEN_IN_SELECTED_DOMAIN')
