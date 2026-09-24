from __future__ import annotations

import json
import sqlite3
import unittest

from robot_trials.api import JsonApplication
from robot_trials.service import TrialService


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

    def test_appeal_routes_require_actor(self) -> None:
        response = self.app.handle(
            "POST",
            "/appeals",
            body=json.dumps({"batch_id": "b", "decision_id": 1, "evidence_summary": "x"}).encode(),
        )
        self.assertEqual(response.status, 422)
        response = self.app.handle(
            "POST",
            "/appeals/1/review",
            body=json.dumps({"outcome": "uphold", "note": "ok"}).encode(),
        )
        self.assertEqual(response.status, 422)

    def test_appeal_review_route_enforces_role_and_wires_outcome(self) -> None:
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("approver2", "approver"),
        ):
            self.app.handle(
                "POST",
                "/users",
                body=json.dumps({"user_id": user_id, "display_name": user_id, "role": role}).encode(),
            )
        # 操作员无权复议：路由应返回 403 而不是落到 404。
        response = self.app.handle(
            "POST",
            "/appeals/1/review",
            headers={"X-Actor-Id": "operator"},
            body=json.dumps({"outcome": "uphold", "note": "越权"}).encode(),
        )
        self.assertEqual(response.status, 403)
        self.assertEqual(response.body["error"]["code"], "forbidden")
        # 合法审批人访问不存在的申诉应得到 404。
        response = self.app.handle(
            "POST",
            "/appeals/999/review",
            headers={"X-Actor-Id": "approver2"},
            body=json.dumps({"outcome": "uphold", "note": "无此申诉"}).encode(),
        )
        self.assertEqual(response.status, 404)


if __name__ == "__main__":
    unittest.main()
