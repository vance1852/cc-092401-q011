from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from robot_trials.clock import FrozenClock
from robot_trials.errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from robot_trials.jsonio import load_json
from robot_trials.service import TrialService
from robot_trials.storage import connect


ROOT = Path(__file__).resolve().parents[1]


class AppealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = TrialService(self.connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("operator2", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("approver2", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text().splitlines()
            if line.strip()
        ]
        self.service.register_robot("operator", "robot-a", "A 型", "厂商")
        self.service.register_build("operator", "build-a", "robot-a", "1.0", "b" * 64)
        self.service.publish_protocol("stat", self.protocol)
        self.service.create_batch("operator", "batch-a", "demo-delivery-v1", 1, "build-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.import_observations("operator", "batch-a", "key-1", self.rows)

    def tearDown(self) -> None:
        self.connection.close()

    def _decided(self, decision: str = "rejected") -> tuple[int, int]:
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("worker", 30)
        analysis = self.service.complete_job("worker", job["job_id"], "stat")
        result = self.service.decide(
            "approver", "batch-a", analysis["analysis_id"], decision, "初判理由"
        )
        return result["decision_id"], analysis["analysis_id"]

    def test_appeal_and_uphold_keeps_decision_active(self) -> None:
        decision_id, analysis_id = self._decided()
        appeal = self.service.submit_appeal(
            "operator", "batch-a", decision_id, "对规则解释的异议与证据摘要"
        )
        self.assertEqual(appeal["status"], "pending")
        review = self.service.review_appeal(
            "approver2", appeal["appeal_id"], "uphold", "原结论依据充分"
        )
        self.assertEqual(review["outcome"], "uphold")
        row = self.connection.execute(
            "SELECT status FROM decisions WHERE decision_id=?", (decision_id,)
        ).fetchone()
        self.assertEqual(row["status"], "active")

    def test_only_batch_owner_operator_may_appeal(self) -> None:
        decision_id, _ = self._decided()
        with self.assertRaises(Forbidden):
            self.service.submit_appeal("operator2", "batch-a", decision_id, "无权申诉")
        with self.assertRaises(Forbidden):
            self.service.submit_appeal("stat", "batch-a", decision_id, "无权申诉")

    def test_evidence_summary_required(self) -> None:
        decision_id, _ = self._decided()
        with self.assertRaises(ValidationFailed):
            self.service.submit_appeal("operator", "batch-a", decision_id, "  ")

    def test_original_decider_cannot_review(self) -> None:
        decision_id, _ = self._decided()
        appeal = self.service.submit_appeal("operator", "batch-a", decision_id, "异议")
        with self.assertRaises(Forbidden):
            self.service.review_appeal("approver", appeal["appeal_id"], "uphold", "自审")

    def test_only_approver_role_can_review(self) -> None:
        decision_id, _ = self._decided()
        appeal = self.service.submit_appeal("operator", "batch-a", decision_id, "异议")
        for actor in ("operator", "stat", "auditor"):
            with self.assertRaises(Forbidden):
                self.service.review_appeal(actor, appeal["appeal_id"], "uphold", "越权")

    def test_duplicate_pending_appeal_blocked(self) -> None:
        decision_id, _ = self._decided()
        self.service.submit_appeal("operator", "batch-a", decision_id, "第一次申诉")
        with self.assertRaises(Conflict):
            self.service.submit_appeal("operator", "batch-a", decision_id, "重复申诉")

    def test_appeal_allowed_only_once_per_decision(self) -> None:
        decision_id, _ = self._decided()
        appeal = self.service.submit_appeal("operator", "batch-a", decision_id, "申诉")
        self.service.review_appeal("approver2", appeal["appeal_id"], "uphold", "维持")
        with self.assertRaises(Conflict):
            self.service.submit_appeal("operator", "batch-a", decision_id, "再次申诉")

    def test_expired_decision_cannot_be_appealed(self) -> None:
        decision_id, _ = self._decided()
        self.clock.advance(days=31)
        with self.assertRaises(InvalidState):
            self.service.submit_appeal("operator", "batch-a", decision_id, "超期申诉")

    def test_cannot_appeal_unknown_or_foreign_decision(self) -> None:
        decision_id, _ = self._decided()
        with self.assertRaises(NotFound):
            self.service.submit_appeal("operator", "batch-a", 9999, "不存在")
        with self.assertRaises(NotFound):
            self.service.submit_appeal("operator", "other-batch", decision_id, "跨批次")

    def test_decide_blocked_while_appeal_pending(self) -> None:
        decision_id, analysis_id = self._decided()
        self.service.submit_appeal("operator", "batch-a", decision_id, "申诉中")
        with self.assertRaises(InvalidState):
            self.service.decide("approver2", "batch-a", analysis_id, "approved", "抢裁决")

    def test_double_adjudication_blocked_across_connections(self) -> None:
        decision_id, _ = self._decided()
        appeal_id = self.service.submit_appeal(
            "operator", "batch-a", decision_id, "申诉"
        )["appeal_id"]
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "concurrency.sqlite3"
            target = connect(database)
            try:
                self.connection.backup(target)
            finally:
                target.close()
            connection_a = connect(database)
            connection_b = connect(database)
            try:
                service_a = TrialService(connection_a, self.clock)
                service_b = TrialService(connection_b, self.clock)
                service_a.review_appeal("approver2", appeal_id, "uphold", "裁决 A")
                with self.assertRaises((Conflict, InvalidState)):
                    service_b.review_appeal("approver", appeal_id, "revoke", "裁决 B")
            finally:
                connection_a.close()
                connection_b.close()
            verify = connect(database)
            try:
                status = verify.execute(
                    "SELECT reviewed_by,status FROM appeals WHERE appeal_id=?", (appeal_id,)
                ).fetchone()
                self.assertEqual(status["reviewed_by"], "approver2")
                self.assertEqual(status["status"], "upheld")
            finally:
                verify.close()

    def test_revoke_keeps_history_and_blocks_redecision(self) -> None:
        decision_id, _ = self._decided()
        appeal = self.service.submit_appeal("operator", "batch-a", decision_id, "证据有误")
        self.service.review_appeal("approver2", appeal["appeal_id"], "revoke", "撤销原决定")
        row = self.connection.execute(
            "SELECT status,revoked_by,revoke_reason FROM decisions WHERE decision_id=?",
            (decision_id,),
        ).fetchone()
        self.assertEqual(row["status"], "revoked")
        self.assertEqual(row["revoked_by"], "approver2")
        # 旧记录必须保留：分析、决定、申诉均仍可查询。
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM decisions").fetchone()[0], 1
        )
        with self.assertRaises(InvalidState):
            self.service.submit_appeal("operator", "batch-a", decision_id, "对撤销决定再申诉")
        # 批次仍停留在 decided，不允许在原修订上再次决定
        report = self.service.report("auditor", "batch-a")
        self.assertIsNone(report["current_effective"])

    def test_reanalyze_creates_revision_and_new_decision_supersedes_old(self) -> None:
        observation_id = self.connection.execute(
            "SELECT observation_id FROM observations ORDER BY observation_id LIMIT 1"
        ).fetchone()[0]
        requested = self.service.request_exclusion("operator", observation_id, "记录失效")
        self.service.review_exclusion("stat", requested["exclusion_id"], True, "批准排除")
        decision_id, old_analysis_id = self._decided()
        appeal = self.service.submit_appeal(
            "operator", "batch-a", decision_id, "补交补充材料并申请变更排除"
        )
        review = self.service.review_appeal(
            "approver2", appeal["appeal_id"], "reanalyze",
            "补充一条复测观测，并基于排除变更重新分析",
        )
        new_batch_id = review["reanalysis_batch_id"]
        self.assertEqual(new_batch_id, "batch-a#r1")
        new_batch = self.service.get_batch(new_batch_id)
        self.assertEqual(new_batch["state"], "running")
        self.assertEqual(new_batch["reanalysis_of_batch"], "batch-a")
        # 原批次旧记录保留，旧决定被标记为 superseded 而非删除。
        old = self.connection.execute(
            "SELECT status FROM decisions WHERE decision_id=?", (decision_id,)
        ).fetchone()
        self.assertEqual(old["status"], "superseded")
        # 观测与已批准排除被复制到新修订。
        copied = self.connection.execute(
            "SELECT count(*) FROM observations WHERE batch_id=?", (new_batch_id,)
        ).fetchone()[0]
        self.assertEqual(copied, 6)
        copied_exclusions = self.connection.execute(
            "SELECT count(*) FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
            "WHERE o.batch_id=? AND e.status='approved'", (new_batch_id,)
        ).fetchone()[0]
        self.assertEqual(copied_exclusions, 1)
        # 补充材料：新批次允许导入新的复测观测。
        extra = dict(self.rows[0])
        extra["source_row"] = "007"
        self.service.import_observations("operator", new_batch_id, "supplement-1", [extra])
        # 原批次不能再形成决定，必须在新修订上引用最新分析。
        with self.assertRaises(InvalidState):
            self.service.decide("approver", "batch-a", old_analysis_id, "approved", "旧修订裁决")
        self.service.seal_batch("stat", new_batch_id, 1)
        job = self.service.claim_job("worker-2", 30)
        analysis = self.service.complete_job("worker-2", job["job_id"], "stat")
        self.service.decide(
            "approver", new_batch_id, analysis["analysis_id"], "approved", "基于补充材料准入"
        )
        # 新决定不能引用旧分析。
        with self.assertRaises(NotFound):
            self.service.decide("approver2", new_batch_id, old_analysis_id, "approved", "引用过期分析")
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(report["lineage"], ["batch-a", "batch-a#r1"])
        self.assertEqual(
            report["current_effective"]["decision"]["decision_id"],
            self.connection.execute(
                "SELECT decision_id FROM decisions WHERE batch_id=?", (new_batch_id,)
            ).fetchone()[0],
        )
        self.assertEqual(
            [item["status"] for item in report["current_effective"]["supersedes"]],
            ["superseded"],
        )
        kinds = [item["kind"] for item in report["timeline"]]
        self.assertEqual(
            kinds,
            [
                "analysis", "decision", "appeal", "appeal_review", "revision",
                "analysis", "decision",
            ],
        )

    def _finish_revision(self, batch_id: str, worker: str, approver: str, decision: str, reason: str) -> int:
        """封存并重分析一个修订批次，形成新决定；返回新决定编号。"""

        revision = self.service.get_batch(batch_id)
        self.service.seal_batch("stat", batch_id, revision["revision"])
        job = self.service.claim_job(worker, 30)
        analysis = self.service.complete_job(worker, job["job_id"], "stat")
        result = self.service.decide(
            approver, batch_id, analysis["analysis_id"], decision, reason
        )
        return result["decision_id"]

    def test_second_reanalysis_naming_lineage_and_supersession_link(self) -> None:
        decision_id, _ = self._decided()
        # 第一次复议：重新分析 -> #r1 并形成新决定。
        appeal = self.service.submit_appeal("operator", "batch-a", decision_id, "补交材料一")
        review = self.service.review_appeal(
            "approver2", appeal["appeal_id"], "reanalyze", "排除变更一"
        )
        first_revision = review["reanalysis_batch_id"]
        self.assertEqual(first_revision, "batch-a#r1")
        new_decision_id = self._finish_revision(
            first_revision, "worker-2", "approver", "approved", "修订一决定"
        )
        # 第二次申诉必须针对当前有效（#r1）决定，由另一名审批人复议。
        appeal2 = self.service.submit_appeal(
            "operator", first_revision, new_decision_id, "补交材料二"
        )
        review2 = self.service.review_appeal(
            "approver2", appeal2["appeal_id"], "reanalyze", "排除变更二"
        )
        second_revision = review2["reanalysis_batch_id"]
        self.assertEqual(second_revision, "batch-a#r2")
        final_decision_id = self._finish_revision(
            second_revision, "worker-3", "approver", "approved", "修订二决定"
        )
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(report["lineage"], ["batch-a", "batch-a#r1", "batch-a#r2"])
        self.assertEqual(
            report["current_effective"]["decision"]["decision_id"], final_decision_id
        )
        superseded_links = {
            item["decision_id"]: item["superseded_by_decision_id"]
            for item in report["current_effective"]["supersedes"]
        }
        # 每一份旧决定都由紧邻的下一份决定取代：根 -> #r1 决定 -> #r2 决定。
        self.assertEqual(superseded_links[decision_id], new_decision_id)
        self.assertEqual(superseded_links[new_decision_id], final_decision_id)
        # 各历史决定仍被保留。
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM decisions WHERE status='superseded'"
            ).fetchone()[0],
            2,
        )

    def test_reanalyze_requires_explicit_change_note(self) -> None:
        decision_id, _ = self._decided()
        appeal = self.service.submit_appeal("operator", "batch-a", decision_id, "申诉")
        with self.assertRaises(ValidationFailed):
            self.service.review_appeal("approver2", appeal["appeal_id"], "reanalyze", "  ")

    def test_review_unknown_or_closed_appeal(self) -> None:
        decision_id, _ = self._decided()
        appeal = self.service.submit_appeal("operator", "batch-a", decision_id, "申诉")
        self.service.review_appeal("approver2", appeal["appeal_id"], "uphold", "维持")
        with self.assertRaises(InvalidState):
            self.service.review_appeal("approver2", appeal["appeal_id"], "revoke", "重复裁决")
        with self.assertRaises(NotFound):
            self.service.review_appeal("approver2", 9999, "uphold", "不存在")


if __name__ == "__main__":
    unittest.main()
