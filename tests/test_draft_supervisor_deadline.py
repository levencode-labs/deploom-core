"""Completed workers cannot overrule the run's absolute publication cutoff.

The clocks are advanced by the worker, so the completion/deadline ordering is
deterministic and does not depend on scheduler timing or a real network delay.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import requests

import dependency_live_roadmap_generator as core


class DraftSupervisorDeadlineTests(unittest.TestCase):
    def exercise(self, *, planning, error, elapsed, coarse_elapsed=None):
        now = {"precise": 0.0, "coarse": 0.0}
        rows = {"fixture": ["original"]}
        failure = requests.exceptions.ReadTimeout("deterministic read timeout")
        value = object()

        def worker(working=None):
            if working is not None:
                working["fixture"][:] = ["changed"]
            now["precise"] = elapsed
            now["coarse"] = elapsed if coarse_elapsed is None else coarse_elapsed
            if error:
                raise failure
            return value

        with (patch.object(core.time, "monotonic", side_effect=lambda: now["coarse"]),
              patch.object(core.time, "perf_counter", side_effect=lambda: now["precise"]),
              patch.object(core, "DRAFT_FINALIZE_RESERVE_SECONDS", 1.0)):
            clock = core.DeadlineClock(10.0)
            try:
                if planning:
                    result = core.run_supervised_planning("test", clock, worker, rows)
                else:
                    result = core.run_supervised("test", clock, worker)
            except BaseException as exc:
                result = exc
        return result, rows, failure, value

    def test_completed_error_at_cutoff_is_deadline_not_network_failure(self):
        for planning in (False, True):
            with self.subTest(planning=planning):
                result, rows, _, _ = self.exercise(planning=planning, error=True, elapsed=9.0)
                self.assertIsInstance(result, core.DraftBudgetExceeded)
                self.assertEqual("test", result.phase)
                self.assertEqual({"fixture": ["original"]}, rows)

    def test_completed_success_at_cutoff_is_not_published(self):
        for planning in (False, True):
            with self.subTest(planning=planning):
                result, rows, _, _ = self.exercise(planning=planning, error=False, elapsed=9.0)
                self.assertIsInstance(result, core.DraftBudgetExceeded)
                self.assertEqual({"fixture": ["original"]}, rows)

    def test_windows_coarse_clock_cannot_hide_elapsed_deadline(self):
        # CPython 3.12 on Windows uses GetTickCount64 for monotonic(), while
        # perf_counter() measures finer elapsed time. Model the prior tick.
        for planning in (False, True):
            with self.subTest(planning=planning):
                result, rows, _, _ = self.exercise(
                    planning=planning, error=True, elapsed=9.0, coarse_elapsed=8.984375,
                )
                self.assertIsInstance(result, core.DraftBudgetExceeded)
                self.assertEqual({"fixture": ["original"]}, rows)

    def test_on_time_errors_keep_the_original_exception(self):
        for planning in (False, True):
            with self.subTest(planning=planning):
                result, rows, failure, _ = self.exercise(planning=planning, error=True, elapsed=1.0)
                self.assertIs(failure, result)
                self.assertEqual({"fixture": ["original"]}, rows)

    def test_on_time_success_is_preserved(self):
        for planning in (False, True):
            with self.subTest(planning=planning):
                result, rows, _, value = self.exercise(planning=planning, error=False, elapsed=1.0)
                self.assertIs(value, result)
                self.assertEqual({"fixture": ["changed" if planning else "original"]}, rows)

    def test_completed_late_prefetch_cannot_publish_worker_cache(self):
        client = core.LiveDataClient("https://registry.example.invalid", timeout=3, batch_size=100, sleep_sec=0)
        self.addCleanup(client.session.close)
        original = {"KEPT": {"id": "KEPT"}}
        client.vuln_detail_cache.update(original)
        now = [0.0]

        def fetch(worker, identifier):
            self.assertIsNot(client, worker)
            value = {"id": identifier}
            worker.vuln_detail_cache[identifier] = value
            now[0] = 9.0
            return value

        with (patch.object(core.time, "monotonic", side_effect=lambda: now[0]),
              patch.object(core.time, "perf_counter", side_effect=lambda: now[0]),
              patch.object(core, "DRAFT_FINALIZE_RESERVE_SECONDS", 1.0),
              patch.object(core.LiveDataClient, "fetch_osv_vuln", fetch)):
            client.set_deadline(core.DeadlineClock(10.0))
            with self.assertRaises(core.DraftBudgetExceeded):
                client._prefetch_osv_details(["A", "B"])
        self.assertEqual(original, client.vuln_detail_cache)


if __name__ == "__main__":
    unittest.main()
