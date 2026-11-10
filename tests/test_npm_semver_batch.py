"""Batch identity, bounds and differential npm-semver behavior."""
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from draft_npm_preflight import _npm_command
from npm_semver_batch import _outcomes, match_npm_semver_many
from verification_process_supervisor import run_supervised


def response(argv, cwd, **kwargs):
    payload = json.loads(Path(argv[-1]).read_text())
    return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({
        'schemaVersion': 1, 'batchId': payload['batchId'],
        'results': [{'id': row['id'], 'outcome': 'MATCH'} for row in payload['pairs']],
    }))


class BatchProtocolTests(unittest.TestCase):
    def test_response_ids_are_exact_unique_and_typed(self):
        valid = {'schemaVersion': 1, 'batchId': 'batch', 'results': [
            {'id': 1, 'outcome': 'NO_MATCH'}, {'id': 0, 'outcome': 'MATCH'}]}
        self.assertEqual(_outcomes(json.dumps(valid), 'batch', 2), [True, False])
        for change in (
            {'batchId': 'other'}, {'schemaVersion': True}, {'extra': 1},
            {'results': [{'id': 0, 'outcome': 'MATCH'}]},
            {'results': [{'id': 0, 'outcome': 'MATCH'}, {'id': 0, 'outcome': 'NO_MATCH'}]},
            {'results': [{'id': False, 'outcome': 'MATCH'}, {'id': 1, 'outcome': 'NO_MATCH'}]},
            {'results': [{'id': 0, 'outcome': True}, {'id': 1, 'outcome': 'NO_MATCH'}]},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                _outcomes(json.dumps({**valid, **change}), 'batch', 2)
        with self.assertRaises(ValueError):
            _outcomes('{"schemaVersion":1,"schemaVersion":1,"batchId":"batch","results":[]}', 'batch', 0)

    def test_one_process_per_batch_and_no_node_preload(self):
        with patch('npm_semver_batch._npm_command', return_value=['node', '/prepared/npm/bin/npm-cli.js']), patch(
            'npm_semver_batch.run_supervised', side_effect=response,
        ) as run, patch.dict('os.environ', {'NODE_OPTIONS': '--require=untrusted', 'NODE_PATH': '/project'}):
            result = match_npm_semver_many([('^1', '1.0.0')] * 100)
        self.assertEqual(result, [True] * 100)
        run.assert_called_once()
        self.assertNotIn('NODE_OPTIONS', run.call_args.kwargs['base_env'])
        self.assertNotIn('NODE_PATH', run.call_args.kwargs['base_env'])
        self.assertLessEqual(run.call_args.kwargs['timeout_seconds'], 5)

    def test_completed_batches_survive_later_timeout(self):
        calls = 0
        def run(argv, cwd, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise subprocess.TimeoutExpired(argv, kwargs['timeout_seconds'])
            return response(argv, cwd, **kwargs)
        with patch('npm_semver_batch._npm_command', return_value=['node', '/prepared/npm/bin/npm-cli.js']), patch(
            'npm_semver_batch.run_supervised', side_effect=run,
        ):
            result = match_npm_semver_many([('^1', '1.0.0')] * 260)
        self.assertEqual(result, [True] * 256 + [None] * 4)

    def test_invalid_or_truncated_batch_never_becomes_clean(self):
        for truncated, stdout, code in ((True, '{}', 0), (False, '{}', 0), (False, 'false', 0), (False, '', 2)):
            result = subprocess.CompletedProcess([], code, stdout=stdout)
            result.output_truncated = truncated
            with patch('npm_semver_batch._npm_command', return_value=['node', '/prepared/npm/bin/npm-cli.js']), patch(
                'npm_semver_batch.run_supervised', return_value=result,
            ):
                self.assertEqual(match_npm_semver_many([('^1', '1.0.0')]), [None])

    def test_input_and_expired_budget_do_not_launch_worker(self):
        with patch('npm_semver_batch._npm_command', return_value=['node', '/prepared/npm/bin/npm-cli.js']), patch(
            'npm_semver_batch.run_supervised', side_effect=AssertionError('worker must not start'),
        ):
            self.assertEqual(match_npm_semver_many([('x' * (2 * 1024 * 1024), '1.0.0')]), [None])
            self.assertEqual(match_npm_semver_many([('^1', '1.0.0')], timeout_seconds=0), [None])


class NativeSemverTests(unittest.TestCase):
    def test_same_results_as_scalar_npm_semver_in_one_process(self):
        try:
            node, npm = _npm_command()
        except OSError as exc:
            self.skipTest(str(exc))
        semver = Path(npm).resolve().parent.parent / 'node_modules' / 'semver'
        pairs = [('^1.2.0', '1.3.0'), ('~1.2.0', '1.3.0'), ('>=1 <2 || >=3', '3.1.0'),
                 ('>=1.2.3-alpha.1 <2', '1.2.3-alpha.2'), ('^1', '1.5.0-beta.1'),
                 (' =v1.2.3 ', '1.2.3'), ('invalid-range', '1.2.3'), ('1.2.x', '1.2.9')]
        script = ("const s=require(process.argv[1]);const [r,v]=JSON.parse(process.argv[2]);"
                  "const o={includePrerelease:true,loose:true};process.stdout.write(JSON.stringify("
                  "s.validRange(r,o)===null?null:s.satisfies(v,r,o)));")
        expected = [json.loads(subprocess.run([node, '-e', script, str(semver), json.dumps(pair)],
                    check=True, capture_output=True, text=True, timeout=5).stdout) for pair in pairs]
        with patch('npm_semver_batch.run_supervised', wraps=run_supervised) as run:
            actual = match_npm_semver_many(pairs)
        self.assertEqual(actual, expected)
        run.assert_called_once()
