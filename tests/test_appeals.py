from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path

from robot_trials.clock import FrozenClock
from robot_trials.errors import Conflict, Forbidden, InvalidState, ValidationFailed
from robot_trials.jsonio import load_json
from robot_trials.service import TrialService


ROOT = Path(__file__).resolve().parents[1]


class AppealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = TrialService(self.connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("other-operator", "operator"),
            ("stat", "statistician"),
            ("approver-1", "approver"),
            ("approver-2", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_robot("operator", "robot-a", "A 型", "厂商")
        self.service.register_build("operator", "build-a", "robot-a", "1.0", "b" * 64)
        self.service.publish_protocol("stat", self.protocol)
        self.service.create_batch("operator", "batch-a", "demo-delivery-v1", 1, "build-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.import_observations("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("worker", 30)
        self.analysis_v2 = self.service.complete_job("worker", job["job_id"], "stat")
        self.service.decide(
            "approver-1", "batch-a", self.analysis_v2["analysis_id"], "rejected", "规则不达标"
        )
        self.decision_id = self.connection.execute(
            "SELECT decision_id FROM decisions ORDER BY decision_id DESC LIMIT 1"
        ).fetchone()[0]

    def tearDown(self) -> None:
        self.connection.close()

    def _supplementary_rows(self) -> list[dict]:
        return [
            {
                "source_batch": "hall-a-supplement",
                "source_row": f"s-{index:03d}",
                "robot_id": "robot-a",
                "protocol_id": "demo-delivery-v1",
                "protocol_version": 1,
                "stratum_key": "cross-traffic",
                "observed_at": "2026-09-22T10:00:00+08:00",
                "metrics": {"completed": 1, "completion_seconds": "39.5", "interventions": 0},
                "excluded_reason": None,
            }
            for index in range(3)
        ]

    def _reanalyze_to_new_decision(self) -> dict:
        appeal = self.service.submit_appeal("operator", self.decision_id, "排除依据有误并补交三组记录")
        self.clock.advance(minutes=10)
        ruling = self.service.review_appeal(
            "approver-2", appeal["appeal_id"], "reanalyze", "按补充材料重新分析",
            reanalysis_directive="补交三组 cross-traffic 记录后重新分析",
        )
        self.assertIsNone(self.service.claim_job("worker", 30))
        self.clock.advance(minutes=10)
        self.service.import_observations(
            "operator", "batch-a", "key-supplement", self._supplementary_rows()
        )
        self.clock.advance(minutes=10)
        self.service.seal_batch("stat", "batch-a", ruling["reanalysis_batch_revision"])
        self.clock.advance(minutes=10)
        job = self.service.claim_job("worker", 30)
        self.assertEqual(job["batch_revision"], ruling["reanalysis_batch_revision"])
        new_analysis = self.service.complete_job("worker", job["job_id"], "stat")
        self.clock.advance(minutes=10)
        return {"appeal": appeal, "ruling": ruling, "analysis": new_analysis}

    def test_full_reanalysis_cycle_replaces_conclusion_without_deleting_history(self) -> None:
        outcome = self._reanalyze_to_new_decision()
        new_analysis_id = outcome["analysis"]["analysis_id"]
        self.assertNotEqual(new_analysis_id, self.analysis_v2["analysis_id"])

        batch = self.service.get_batch("batch-a")
        self.assertEqual(batch["state"], "analyzed")
        with self.assertRaises(InvalidState):
            self.service.decide("approver-2", "batch-a", self.analysis_v2["analysis_id"], "approved", "旧分析")
        self.service.decide("approver-2", "batch-a", new_analysis_id, "approved", "补充材料后达标")

        old_decision = self.connection.execute(
            "SELECT * FROM decisions WHERE decision_id=?", (self.decision_id,)
        ).fetchone()
        self.assertEqual(old_decision["decision"], "rejected")
        self.assertIsNotNone(old_decision["superseded_by_appeal_id"])
        analysis_count = self.connection.execute("SELECT count(*) FROM analyses").fetchone()[0]
        self.assertEqual(analysis_count, 2)

        report = self.service.report("auditor", "batch-a")
        kinds = [entry["kind"] for entry in report["timeline"]]
        self.assertEqual(
            kinds, ["decision", "appeal", "analysis", "review", "analysis", "decision"]
        )
        self.assertEqual(report["current"]["effective_decision"]["decision"], "approved")
        self.assertEqual(report["current"]["effective_decision"]["effective_status"], "in_force")
        self.assertEqual(report["current"]["effective_analysis_id"], new_analysis_id)
        first_decision = report["timeline"][0]["item"]
        self.assertTrue(first_decision["superseded"])
        self.assertEqual(first_decision["effect"], "superseded_by_reanalysis")

    def test_uphold_keeps_decision_in_force_and_blocks_reappeal(self) -> None:
        appeal = self.service.submit_appeal("operator", self.decision_id, "请求复议")
        ruling = self.service.review_appeal("approver-2", appeal["appeal_id"], "uphold", "理由不成立")
        self.assertEqual(ruling["status"], "upheld")
        self.assertEqual(self.service.get_batch("batch-a")["state"], "decided")
        with self.assertRaises(Conflict):
            self.service.submit_appeal("operator", self.decision_id, "再次申诉")
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(
            report["current"]["effective_decision"]["effective_status"], "in_force"
        )
        self.assertEqual(
            report["current"]["effective_analysis_id"], self.analysis_v2["analysis_id"]
        )

    def test_revoke_keeps_record_but_marks_decision_no_longer_effective(self) -> None:
        appeal = self.service.submit_appeal("operator", self.decision_id, "规则解释有误")
        self.service.review_appeal("approver-2", appeal["appeal_id"], "revoke", "撤销原拒绝决定")
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(
            report["current"]["effective_decision"]["effective_status"], "revoked"
        )
        self.assertEqual(report["timeline"][0]["item"]["effect"], "revoked")
        self.assertIsNotNone(
            self.connection.execute(
                "SELECT 1 FROM decisions WHERE decision_id=? AND decision='rejected'",
                (self.decision_id,),
            ).fetchone()
        )

    def test_original_decider_cannot_review_appeal(self) -> None:
        appeal = self.service.submit_appeal("operator", self.decision_id, "证据摘要")
        with self.assertRaises(Forbidden):
            self.service.review_appeal("approver-1", appeal["appeal_id"], "uphold", "维持")

    def test_only_batch_owner_may_appeal(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.submit_appeal("other-operator", self.decision_id, "越权申诉")

    def test_duplicate_pending_appeal_is_rejected(self) -> None:
        self.service.submit_appeal("operator", self.decision_id, "第一次申诉")
        with self.assertRaises(Conflict):
            self.service.submit_appeal("operator", self.decision_id, "重复申诉")

    def test_appeal_after_window_is_rejected(self) -> None:
        self.clock.advance(days=7, seconds=1)
        with self.assertRaises(InvalidState):
            self.service.submit_appeal("operator", self.decision_id, "过期申诉")

    def test_concurrent_double_ruling_is_prevented(self) -> None:
        appeal = self.service.submit_appeal("operator", self.decision_id, "证据")
        self.service.review_appeal("approver-2", appeal["appeal_id"], "uphold", "维持")
        with self.assertRaises(InvalidState):
            self.service.review_appeal("approver-2", appeal["appeal_id"], "revoke", "重复裁决")

    def test_role_boundaries_for_appeal_workflow(self) -> None:
        appeal = self.service.submit_appeal("operator", self.decision_id, "证据")
        with self.assertRaises(Forbidden):
            self.service.review_appeal("stat", appeal["appeal_id"], "uphold", "统计不能复议")
        with self.assertRaises(Forbidden):
            self.service.submit_appeal("approver-2", self.decision_id, "审批人不能代申诉")

    def test_decision_before_reanalysis_must_not_reference_stale_analysis(self) -> None:
        outcome = self._reanalyze_to_new_decision()
        with self.assertRaises(InvalidState):
            self.service.decide(
                "approver-1", "batch-a", self.analysis_v2["analysis_id"], "approved", "引用过期分析"
            )
        self.service.decide(
            "approver-1", "batch-a", outcome["analysis"]["analysis_id"], "approved", "引用最新分析"
        )

    def test_unknown_appeal_and_actions_are_validated(self) -> None:
        with self.assertRaises(Exception):
            self.service.review_appeal("approver-2", 999, "uphold", "不存在")
        appeal = self.service.submit_appeal("operator", self.decision_id, "证据")
        with self.assertRaises(Exception):
            self.service.review_appeal("approver-2", appeal["appeal_id"], "discard", "非法动作")

    def test_reanalyze_requires_explicit_directive(self) -> None:
        appeal = self.service.submit_appeal("operator", self.decision_id, "证据")
        with self.assertRaises(ValidationFailed):
            self.service.review_appeal("approver-2", appeal["appeal_id"], "reanalyze", "重新分析")

    def test_appeal_requires_evidence_summary(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.submit_appeal("operator", self.decision_id, "  ")


if __name__ == "__main__":
    unittest.main()
