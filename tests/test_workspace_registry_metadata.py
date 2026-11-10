import threading
import time
import unittest
from unittest.mock import Mock, patch

from dependency_live_roadmap_generator import DeadlineClock, DraftBudgetExceeded, LiveDataClient
from workspace_peer_model import plan_workspace_from_registry
from workspace_registry_metadata import fetch_workspace_packuments


class WorkspaceMetadataTests(unittest.TestCase):
    def client(self, seconds=5):
        client = LiveDataClient('https://registry.example.invalid', timeout=1, batch_size=8, sleep_sec=0)
        client.set_deadline(DeadlineClock(seconds))
        self.addCleanup(client.session.close)
        return client

    def test_four_concurrent_reads_deduplicated_no_shared_cache_or_late_progress(self):
        client = self.client()
        barrier = threading.Barrier(4)
        lock = threading.Lock()
        active = peak = 0
        workers = []
        def create(_):
            worker = Mock()
            workers.append(worker)
            def fetch(name):
                nonlocal active, peak
                self.assertIsNone(worker.metadata_cache_dir)
                self.assertEqual(worker.metadata_cache_ttl, 0)
                with lock:
                    active += 1
                    peak = max(peak, active)
                barrier.wait(timeout=2)
                with lock:
                    active -= 1
                return {'name': name}, True
            worker._fetch_npm_metadata_result.side_effect = fetch
            return worker
        with patch('dependency_live_roadmap_generator._registry_prefetch_client', side_effect=create):
            result = fetch_workspace_packuments(client, ['p'+str(i) for i in range(8)] + ['p0'])
        self.assertEqual(list(result), ['p'+str(i) for i in range(8)])
        self.assertEqual(peak, 4)
        self.assertEqual(len(workers), 8)
        self.assertEqual(client.npm_cache, {})
        for worker in workers:
            worker.session.close.assert_called_once()

    def test_private_session_is_sequential(self):
        client = self.client()
        client.session.headers['Authorization'] = 'synthetic'
        client.fetch_npm_metadata = Mock(side_effect=lambda name: {'name': name})
        with patch('dependency_live_roadmap_generator._registry_prefetch_client', side_effect=AssertionError('fork')):
            self.assertEqual(len(fetch_workspace_packuments(client, ['one', 'two'])), 2)
        self.assertEqual(client.fetch_npm_metadata.call_count, 2)

    def test_stateful_response_discards_every_speculative_result(self):
        client = self.client()
        client.fetch_npm_metadata = Mock(side_effect=lambda name: {'ordered': name})
        worker = Mock()
        worker._fetch_npm_metadata_result.side_effect = lambda name: ({'speculative': name}, False)
        with patch('dependency_live_roadmap_generator._registry_prefetch_client', return_value=worker):
            result = fetch_workspace_packuments(client, ['one', 'two'])
        self.assertEqual(result, {'one': {'ordered': 'one'}, 'two': {'ordered': 'two'}})

    def test_deadline_returns_without_publishing_late_results(self):
        client = self.client(.08)
        release = threading.Event()
        finished = threading.Event()
        workers = []
        def create(_):
            worker = Mock()
            workers.append(worker)
            def fetch(name):
                release.wait(timeout=2)
                finished.set()
                return {'late': name}, True
            worker._fetch_npm_metadata_result.side_effect = fetch
            return worker
        start = time.monotonic()
        try:
            with patch('dependency_live_roadmap_generator._registry_prefetch_client', side_effect=create):
                with self.assertRaises(DraftBudgetExceeded):
                    fetch_workspace_packuments(client, ['one', 'two'])
            self.assertLess(time.monotonic() - start, 1)
        finally:
            release.set()
        self.assertTrue(finished.wait(timeout=2))
        self.assertEqual(client.npm_cache, {})
        self.assertTrue(all(worker.metadata_cache_dir is None for worker in workers))

    def test_all_local_slots_are_validated_before_network(self):
        client = self.client()
        client.fetch_npm_metadata = Mock(side_effect=AssertionError('network'))
        declarations = {('.', 'dependencies', 'a'): '1.0.0', ('.', 'dependencies', 'z'): '1.0.0'}
        result = plan_workspace_from_registry({'node_modules/a': {'version': '1.0.0'}},
                                              declarations, {}, {}, client, prefetch_metadata=True)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertIn('WORKSPACE_SLOT_UNPROVEN', result['reason'])
        client.fetch_npm_metadata.assert_not_called()
