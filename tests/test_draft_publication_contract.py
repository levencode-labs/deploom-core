from __future__ import annotations

"""Headless Draft publication contracts extracted from the legacy Draft suite.

No Desktop files, npm install, browser, registry request or migration run.
These tests exercise the real Core data types, plan builder and artifact writer.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import dependency_live_roadmap_generator as roadmap


def unknown_row() -> roadmap.DependencyRow:
    return roadmap.DependencyRow(
        project="tiny-basic",
        package_dir="C:/projects/tiny-basic",
        name="uuid",
        kind="runtime",
        requested_spec="10.0.0",
        current_version="10.0.0",
        current_source="package-lock.json",
        latest_version="registry unavailable",
        current_vulns="unknown",
        min_no_critical="неизвестно",
        min_no_high="неизвестно",
        min_no_vuln="неизвестно",
        min_lag_12m="—",
        min_lag_9m="—",
        min_lag_6m="—",
        min_lag_3m="—",
        group=2,
        reason="synthetic metadata unavailable",
        notes="",
    )


def unknown_health() -> roadmap.ProjectHealth:
    return roadmap.ProjectHealth(
        project="tiny-basic", status="yellow", status_rank=1,
        total=1, lag_ok_12m=0, lag_bad_12m=0, lag_ok_pct=100.0,
        critical=0, high=0, moderate=0, low=0, unknown=1,
        reason="lag-policy target неизвестен для 1 зависимостей",
        lag_unknown=1, lag_needed_for_yellow=0,
        yellow_plan_required=0, yellow_projected_lag_ok=0,
        yellow_projected_lag_pct=100.0, yellow_plan_shortfall=0,
    )


class DraftPublicationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old_artifacts_base = list(roadmap._ARTIFACTS_BASE_FOR_DRAFT)

    def tearDown(self) -> None:
        # The source-level artifact-base override is process-global. Never leak
        # this test's temporary output root into a following contract test.
        roadmap._ARTIFACTS_BASE_FOR_DRAFT = self.old_artifacts_base

    def _publish(self, run_id: str, *, status: str = "DRAFT_READY",
                 input_hashes: dict[str, str] | None = None,
                 deadline: roadmap.DeadlineClock | None = None) -> dict:
        return roadmap.publish_draft_result(
            run_id=run_id,
            workspace_id="ws-test",
            project_id="tiny-basic",
            mode="draft",
            rows_by_project={"tiny-basic": [unknown_row()]},
            projects_by_name={},
            health_by_project={"tiny-basic": unknown_health()},
            status=status,
            partial_reason=("synthetic deadline" if status == "DRAFT_PARTIAL" else None),
            deadline=deadline if deadline is not None else roadmap.DeadlineClock(None),
            input_hashes=input_hashes,
        )

    def test_unknown_registry_metadata_cannot_create_an_upgrade_target(self) -> None:
        row = unknown_row()
        self.assertFalse(roadmap._row_metadata_known(row))
        target = roadmap._draft_target_for_major(row)
        self.assertEqual(roadmap.NO_ACTION, target)
        self.assertEqual("unknown-metadata", roadmap._draft_row_status(row, target))
        plan = roadmap.build_draft_plan(
            {"tiny-basic": [row]}, {}, {"tiny-basic": unknown_health()},
        )
        self.assertEqual(1, plan["counts"]["unknown-metadata"])
        self.assertEqual(0, plan["counts"]["proposed"])
        self.assertEqual(["uuid"], [item["package"] for item in plan["unknowns"]])
        self.assertIsNone(plan["proposals"][0]["rows"][0]["target"])

    def test_ready_draft_creates_run_scoped_files_without_claiming_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            roadmap.set_draft_artifacts_base(base)
            manifest = self._publish("run-contract-ready")
            folder = base / "runs" / "run-contract-ready" / "draft"
            for name in ("result.json", "plan.json", "prompt.md", "summary.md"):
                with self.subTest(artifact=name):
                    self.assertTrue((folder / name).is_file())
            self.assertEqual("DRAFT_READY", manifest["status"])
            self.assertEqual("NOT_VERIFIED", manifest["verificationStatus"])
            self.assertEqual("PLANNING_ONLY", manifest["authority"])
            self.assertEqual("UNKNOWN", manifest["compatibility"])
            self.assertEqual(["uuid"], manifest["metadata"]["unknownPackages"])
            self.assertEqual(1, manifest["metadata"]["unknown"])
            self.assertEqual(1, manifest["proposals"]["unknown"])
            prompt = (folder / "prompt.md").read_text(encoding="utf-8")
            self.assertIn("DRAFT BASELINE / PLANNING ONLY", prompt)
            self.assertIn("NOT_VERIFIED", prompt)
            persisted = json.loads((folder / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["runId"], persisted["runId"])

    def test_partial_status_preserves_unverified_authority_and_run_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            roadmap.set_draft_artifacts_base(base)
            ready = self._publish("run-contract-ready")
            partial = self._publish("run-contract-partial", status="DRAFT_PARTIAL")
            self.assertEqual("DRAFT_READY", ready["status"])
            self.assertEqual("DRAFT_PARTIAL", partial["status"])
            self.assertEqual("PLANNING_ONLY", partial["authority"])
            self.assertEqual("NOT_VERIFIED", partial["verificationStatus"])
            self.assertNotEqual(ready["runId"], partial["runId"])
            for run_id in ("run-contract-ready", "run-contract-partial"):
                self.assertTrue((base / "runs" / run_id / "draft" / "plan.json").exists())

    def test_publication_keeps_inventory_time_input_identity(self) -> None:
        # Rebinding to the post-scan filesystem can silently make a stale plan
        # appear fresh. Publication must preserve the inventory-time hash.
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            project = roadmap.ProjectSpec(name="tiny-basic", path=base / "proj", source_branch="main")
            project.path.mkdir(parents=True)
            (project.path / "package.json").write_text(
                '{"name":"proj","version":"1.0.0"}', encoding="utf-8"
            )
            lock = project.path / "package-lock.json"
            lock.write_text("{}", encoding="utf-8")
            (project.path / ".dependency-roadmap").mkdir(parents=True)
            (project.path / ".dependency-roadmap" / "settings.project.json").write_text(
                '{"projects":[{"name":"proj","path":"."}]}', encoding="utf-8"
            )
            old_input_hash = roadmap.draft_input_hash(project)
            lock.write_text('{"changed":true}', encoding="utf-8")
            new_input_hash = roadmap.draft_input_hash(project)
            self.assertNotEqual(old_input_hash, new_input_hash)
            roadmap.set_draft_artifacts_base(base)
            manifest = self._publish("run-inventory-hash", input_hashes={"tiny-basic": old_input_hash})
            self.assertEqual(old_input_hash, manifest["inputHashes"]["tiny-basic"])
            self.assertNotEqual(new_input_hash, manifest["inputHashes"]["tiny-basic"])

    def test_deadline_budget_has_explicit_phase_and_disabled_state(self) -> None:
        clock = roadmap.DeadlineClock(0.001)
        # Move only the synthetic start point, avoiding wall-clock sleeps and
        # scheduler timing in this deadline-state contract.
        clock.started -= 1.0
        with self.assertRaises(roadmap.DraftBudgetExceeded) as caught:
            clock.check("synthetic-phase")
        self.assertEqual("synthetic-phase", caught.exception.phase)
        disabled = roadmap.DeadlineClock(None)
        disabled.check("other-phase")
        snapshot = disabled.as_dict()
        self.assertIsNone(snapshot["deadlineSeconds"])
        self.assertIsNone(snapshot["remainingMs"])

    def test_elapsed_publication_uses_one_clock_when_clock_origins_differ(self) -> None:
        now = [1000.0]
        with (tempfile.TemporaryDirectory() as temporary,
              patch.object(roadmap.time, "monotonic", return_value=100.0),
              patch.object(roadmap.time, "perf_counter", side_effect=lambda: now[0])):
            roadmap.set_draft_artifacts_base(Path(temporary))
            clock = roadmap.DeadlineClock(10.0)
            now[0] = 1002.5
            manifest = self._publish("run-clock-origin", deadline=clock)
            self.assertEqual(2500, manifest["elapsedMs"])
            self.assertEqual(7500, manifest["deadline"]["remainingMs"])
            persisted = json.loads((Path(temporary) / "runs/run-clock-origin/draft/result.json").read_bytes())
            self.assertEqual(2500, persisted["elapsedMs"])


if __name__ == "__main__":
    unittest.main()
