import json
import unittest
from unittest.mock import MagicMock

from semantic_version import NpmSpec, Version

from registry_advisory_evidence import query_registry_advisories


class RegistryAdvisoryEvidenceTests(unittest.TestCase):
    registry = "https://registry.example.test/repository/npm-group"
    advisory = {"id": 12, "name": "sample", "severity": "high", "vulnerable_versions": "<2.0.0"}

    def query(self, body, *, status=200, trust_omissions=False, registry=None, match_limit=None, match_many=None):
        self.session = MagicMock()
        response = self.session.post.return_value.__enter__.return_value
        response.status_code = status
        response.iter_content.return_value = [body if isinstance(body, bytes) else json.dumps(body).encode()]
        return query_registry_advisories(
            self.session, self.registry if registry is None else registry, self.registry,
            [("sample", "1.0.0"), ("sample", "2.0.0"), ("missing", "1.0.0")],
            matches=lambda spec, version: NpmSpec(spec).match(Version(version)),
            match_many=match_many,
            timeout=(1.0, 2.0), trust_omitted_packages=trust_omissions, max_match_evaluations=match_limit,
        )

    def test_exact_pair_and_omission_semantics(self):
        result = self.query({"sample": [self.advisory]})
        affected = result["sample", "1.0.0"]
        self.assertEqual(affected.status, "AFFECTED")
        self.assertEqual(affected.advisories[0].identifier, "12")
        self.assertEqual(affected.source, "REGISTRY_BULK_ADVISORY")
        self.assertEqual(len(affected.response_sha256), 64)
        self.assertEqual(result["sample", "2.0.0"].status, "NO_REPORTED_ADVISORIES")
        self.assertEqual(result["missing", "1.0.0"].reason, "COVERAGE_UNCONFIRMED")
        self.assertEqual(
            self.session.post.call_args.args[0], self.registry + "/-/npm/v1/security/advisories/bulk"
        )
        self.assertFalse(self.session.post.call_args.kwargs["allow_redirects"])
        self.assertEqual(
            self.query({}, trust_omissions=True)["missing", "1.0.0"].status,
            "NO_REPORTED_ADVISORIES",
        )

    def test_untrusted_transport_and_invalid_ranges_fail_closed(self):
        for status in (302, 403, 429, 500):
            with self.subTest(status=status):
                self.assertTrue(all(x.status == "UNKNOWN" for x in self.query({}, status=status).values()))
        result = self.query({"sample": [{**self.advisory, "vulnerable_versions": "unsupported"}]})
        self.assertEqual(result["sample", "1.0.0"].reason, "INVALID_ADVISORY_OR_RANGE")
        result = self.query({}, registry=self.registry + "-other")
        self.assertEqual(result["sample", "1.0.0"].reason, "REGISTRY_NOT_APPROVED")
        self.session.post.assert_not_called()

    def test_match_budget_never_publishes_partially_evaluated_pairs_as_clean(self):
        result = self.query({"sample": [self.advisory]}, match_limit=1)
        self.assertEqual(result["sample", "1.0.0"].status, "AFFECTED")
        self.assertEqual(result["sample", "2.0.0"].status, "UNKNOWN")
        self.assertEqual(result["sample", "2.0.0"].reason, "MATCH_BUDGET_EXHAUSTED")

    def test_duplicate_fields_never_become_empty_evidence(self):
        body = b'{"sample": [], "sample": []}'
        self.assertTrue(all(x.reason == "INVALID_ADVISORY_RESPONSE" for x in self.query(body).values()))

    def test_batch_preserves_findings_coverage_and_global_budget(self):
        from unittest.mock import Mock
        batch = Mock(side_effect=lambda pairs: [NpmSpec(spec).match(Version(version)) for spec, version in pairs])
        result = self.query({'sample': [self.advisory]}, match_many=batch)
        batch.assert_called_once_with([('<2.0.0', '1.0.0'), ('<2.0.0', '2.0.0')])
        self.assertEqual(result['sample', '1.0.0'].status, 'AFFECTED')
        self.assertEqual(result['sample', '2.0.0'].status, 'NO_REPORTED_ADVISORIES')
        self.assertEqual(result['missing', '1.0.0'].reason, 'COVERAGE_UNCONFIRMED')
        batch.reset_mock()
        limited = self.query({'sample': [self.advisory]}, match_many=batch, match_limit=1)
        batch.assert_called_once_with([('<2.0.0', '1.0.0')])
        self.assertEqual(limited['sample', '2.0.0'].reason, 'MATCH_BUDGET_EXHAUSTED')

    def test_batch_protocol_failure_or_unknown_never_certifies_clean(self):
        for outcomes in ([], [True], [False, 'false'], [None, None], {'result': False}):
            with self.subTest(outcomes=outcomes):
                result = self.query({'sample': [self.advisory]}, match_many=lambda _: outcomes)
                self.assertEqual(result['sample', '1.0.0'].status, 'UNKNOWN')
                self.assertEqual(result['sample', '2.0.0'].status, 'UNKNOWN')
        partial = self.query({'sample': [self.advisory]}, match_many=lambda _: [True, None])
        self.assertEqual(partial['sample', '1.0.0'].status, 'AFFECTED')
        self.assertEqual(partial['sample', '2.0.0'].status, 'UNKNOWN')
