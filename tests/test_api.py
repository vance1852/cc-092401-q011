from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path

from robot_trials.api import JsonApplication
from robot_trials.clock import FrozenClock
from robot_trials.jsonio import load_json
from robot_trials.service import TrialService


ROOT = Path(__file__).resolve().parents[1]


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(TrialService(self.connection))

    def tearDown(self) -> None:
        self.connection.close()

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_json_error_shape(self) -> None:
        response = self.app.handle("POST", "/users", body=b"not-json")
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_user_route(self) -> None:
        payload = json.dumps({"user_id": "u1", "display_name": "操作员", "role": "operator"}).encode()
        response = self.app.handle("POST", "/users", body=payload)
        self.assertEqual(response.status, 201)
        self.assertEqual(response.body["role"], "operator")


class AppealApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = TrialService(self.connection, clock)
        self.app = JsonApplication(self.service)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver-1", "approver"),
            ("approver-2", "approver"),
        ):
            self.service.create_user(user_id, user_id, role)
        protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_robot("operator", "robot-a", "A 型", "厂商")
        self.service.register_build("operator", "build-a", "robot-a", "1.0", "b" * 64)
        self.service.publish_protocol("stat", protocol)
        self.service.create_batch("operator", "batch-a", "demo-delivery-v1", 1, "build-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.import_observations("operator", "batch-a", "key-1", rows)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("worker", 30)
        analysis = self.service.complete_job("worker", job["job_id"], "stat")
        self.service.decide("approver-1", "batch-a", analysis["analysis_id"], "rejected", "不达标")
        self.decision_id = self.connection.execute(
            "SELECT decision_id FROM decisions ORDER BY decision_id DESC LIMIT 1"
        ).fetchone()[0]

    def tearDown(self) -> None:
        self.connection.close()

    def _post(self, path: str, actor: str, payload: dict) -> object:
        return self.app.handle(
            "POST", path, headers={"X-Actor-Id": actor}, body=json.dumps(payload).encode()
        )

    def test_appeal_and_review_routes(self) -> None:
        response = self._post(
            f"/decisions/{self.decision_id}/appeals", "operator",
            {"evidence_summary": "对排除规则解释有异议"},
        )
        self.assertEqual(response.status, 201)
        appeal_id = response.body["appeal_id"]

        forbidden = self._post(
            f"/decisions/{self.decision_id}/appeals", "operator",
            {"evidence_summary": "重复申诉"},
        )
        self.assertEqual(forbidden.status, 409)

        original = self._post(f"/appeals/{appeal_id}/review", "approver-1", {"action": "uphold", "note": "x"})
        self.assertEqual(original.status, 403)

        ruling = self._post(
            f"/appeals/{appeal_id}/review", "approver-2",
            {"action": "uphold", "note": "异议不成立"},
        )
        self.assertEqual(ruling.status, 200)
        self.assertEqual(ruling.body["status"], "upheld")


if __name__ == "__main__":
    unittest.main()
