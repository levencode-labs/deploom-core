"""Bounded npm-semver batches using the prepared npm runtime, never project code."""
from __future__ import annotations

from hashlib import sha256
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile
from time import monotonic

from draft_npm_preflight import _npm_command
from verification_process_supervisor import run_supervised

_BATCH_SIZE = 256
_MAX_INPUT_BYTES = 2 * 1024 * 1024
_MAX_OUTPUT_BYTES = 64 * 1024
_SCRIPT = r"""
const semver = require(process.argv[1]);
const payload = JSON.parse(require('node:fs').readFileSync(process.argv[2], 'utf8'));
const opts = {includePrerelease:true, loose:true};
const results = payload.pairs.map(({id, range, version}) => {
  let outcome = 'UNKNOWN';
  try {
    if (semver.validRange(range, opts) !== null) {
      outcome = semver.satisfies(version, range, opts) ? 'MATCH' : 'NO_MATCH';
    }
  } catch (_) {}
  return {id, outcome};
});
process.stdout.write(JSON.stringify({schemaVersion:1, batchId:payload.batchId, results}));
"""


def _unique_object(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate batch response field")
        value[key] = item
    return value


def _outcomes(stdout, batch_id, count):
    if len(stdout.encode('utf-8')) > _MAX_OUTPUT_BYTES:
        raise ValueError('oversized batch response')
    data = json.loads(stdout, object_pairs_hook=_unique_object)
    if (not isinstance(data, dict) or set(data) != {'schemaVersion', 'batchId', 'results'}
            or type(data['schemaVersion']) is not int or data['schemaVersion'] != 1
            or data['batchId'] != batch_id or not isinstance(data['results'], list)
            or len(data['results']) != count):
        raise ValueError('invalid batch response')
    outcomes = {}
    mapping = {'MATCH': True, 'NO_MATCH': False, 'UNKNOWN': None}
    for row in data['results']:
        if (not isinstance(row, dict) or set(row) != {'id', 'outcome'}
                or type(row['id']) is not int or not 0 <= row['id'] < count or row['id'] in outcomes
                or not isinstance(row['outcome'], str) or row['outcome'] not in mapping):
            raise ValueError('invalid batch result')
        outcomes[row['id']] = mapping[row['outcome']]
    return [outcomes[index] for index in range(count)]


def match_npm_semver_many(pairs: list[tuple[str, str]], *, timeout_seconds: float = 5.0) -> list[bool | None]:
    """Use one deadline across all batches; preserve completed batches on failure.

    The trusted emitter has a bounded result per input. The existing supervisor
    bounds merged stdout/stderr and owns timeout, descendant cleanup and reap.
    Any output truncation, nonzero exit or malformed protocol is unknown.
    """
    outcomes = [None] * len(pairs)
    if not pairs or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        return outcomes
    deadline = monotonic() + min(5.0, timeout_seconds)
    try:
        node, npm = _npm_command()
        semver = Path(npm).resolve().parent.parent / 'node_modules' / 'semver'
        # No inherited Node preload or module search path may affect the worker.
        env = {key: value for key, value in os.environ.items()
               if key.upper() not in {'NODE_OPTIONS', 'NODE_PATH'}}
        with tempfile.TemporaryDirectory(prefix='deploom-semver-') as temporary:
            root = Path(temporary)
            source = root / 'pairs.json'
            for offset in range(0, len(pairs), _BATCH_SIZE):
                remaining = deadline - monotonic()
                if remaining <= 0:
                    break
                batch = pairs[offset:offset + _BATCH_SIZE]
                rows = [{'id': index, 'range': spec, 'version': version}
                        for index, (spec, version) in enumerate(batch)]
                encoded = json.dumps(rows, ensure_ascii=True, separators=(',', ':')).encode()
                batch_id = sha256(encoded).hexdigest()
                payload = json.dumps({'schemaVersion': 1, 'batchId': batch_id, 'pairs': rows},
                                     ensure_ascii=True, separators=(',', ':')).encode()
                if len(payload) > _MAX_INPUT_BYTES:
                    continue
                source.write_bytes(payload)
                remaining = deadline - monotonic()
                if remaining <= 0:
                    break
                result = run_supervised(
                    [node, '-e', _SCRIPT, str(semver), str(source)], root,
                    timeout_seconds=remaining, base_env=env, max_output_bytes=_MAX_OUTPUT_BYTES,
                )
                if result.returncode or getattr(result, 'output_truncated', False):
                    break
                outcomes[offset:offset + len(batch)] = _outcomes(result.stdout, batch_id, len(batch))
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return outcomes
