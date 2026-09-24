"""统计准入服务的领域用例。"""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .analysis import ALGORITHM_VERSION, analyze
from .clock import SystemClock, isoformat
from .contracts import Observation, Protocol, ValidationError
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


ROLE_PERMISSIONS = {
    "operator": {
        "catalog.write", "batch.create", "batch.start", "observation.import",
        "exclusion.request", "exclusion.revoke", "appeal.submit",
    },
    "statistician": {"protocol.publish", "batch.seal", "exclusion.review", "analysis.run"},
    "approver": {"decision.write", "appeal.review"},
    "auditor": {"report.read", "audit.read"},
}

# 决定作出后的申诉期限；超过期限的决定不再允许提交申诉。
DEFAULT_APPEAL_WINDOW = timedelta(days=30)


class TrialService:
    """在单个 SQLite 连接上提供全部业务操作。"""

    def __init__(
        self,
        connection: sqlite3.Connection,
        clock=None,
        appeal_window: timedelta = DEFAULT_APPEAL_WINDOW,
    ) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.appeal_window = appeal_window
        initialize(connection)

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(payload), self._now()),
        )

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role) VALUES(?,?,?)",
                    (user_id.strip(), display_name.strip(), role),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role}

    def register_robot(
        self, actor_id: str, robot_id: str, model_name: str, vendor: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO robots(robot_id,model_name,vendor,created_at) VALUES(?,?,?,?)",
                    (robot_id, model_name, vendor, self._now()),
                )
                self._audit("robot", robot_id, "robot.registered", actor_id, {"model_name": model_name})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"机器人已存在: {robot_id}") from exc
        return {"robot_id": robot_id, "model_name": model_name, "vendor": vendor}

    def register_build(
        self, actor_id: str, build_id: str, robot_id: str, version: str, content_sha256: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        if len(content_sha256) != 64:
            raise ValidationFailed("构建摘要必须是 64 位 SHA-256")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO builds(build_id,robot_id,version,content_sha256,created_at) VALUES(?,?,?,?,?)",
                    (build_id, robot_id, version, content_sha256.lower(), self._now()),
                )
                self._audit("build", build_id, "build.registered", actor_id, {"robot_id": robot_id, "version": version})
        except sqlite3.IntegrityError as exc:
            raise Conflict("构建编号、版本或摘要冲突") from exc
        return {"build_id": build_id, "robot_id": robot_id, "version": version}

    def publish_protocol(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "protocol.publish")
        try:
            protocol = Protocol.from_dict(raw)
        except ValidationError as exc:
            raise ValidationFailed(str(exc)) from exc
        text = canonical_json(raw)
        digest = content_digest([raw])
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO protocol_catalog(protocol_id,version,title,task_family,canonical_json,content_sha256,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        protocol.protocol_id,
                        protocol.version,
                        protocol.title,
                        protocol.task_family,
                        text,
                        digest,
                        self._now(),
                    ),
                )
                identity = f"{protocol.protocol_id}@{protocol.version}"
                self._audit("protocol", identity, "protocol.published", actor_id, {"sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("协议版本或内容摘要已经存在") from exc
        return {"protocol_id": protocol.protocol_id, "version": protocol.version, "sha256": digest}

    def _protocol(self, protocol_id: str, version: int) -> tuple[Protocol, str]:
        row = self.connection.execute(
            "SELECT canonical_json,content_sha256 FROM protocol_catalog WHERE protocol_id=? AND version=?",
            (protocol_id, version),
        ).fetchone()
        if row is None:
            raise NotFound("协议版本不存在")
        return Protocol.from_dict(json.loads(row["canonical_json"])), row["content_sha256"]

    def create_batch(
        self,
        actor_id: str,
        batch_id: str,
        protocol_id: str,
        protocol_version: int,
        build_id: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "batch.create")
        self._protocol(protocol_id, protocol_version)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO batches(batch_id,protocol_id,protocol_version,build_id,state,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (batch_id, protocol_id, protocol_version, build_id, "draft", actor_id, self._now()),
                )
                self._audit("batch", batch_id, "batch.created", actor_id, {"build_id": build_id})
        except sqlite3.IntegrityError as exc:
            raise Conflict("批次编号冲突或构建不存在") from exc
        return self.get_batch(batch_id)

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            raise NotFound("批次不存在")
        return dict(row)

    def start_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.start")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE batches SET state='running',revision=revision+1,started_at=? "
                "WHERE batch_id=? AND state='draft' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次不是当前草稿版本")
            self._audit("batch", batch_id, "batch.started", actor_id, {"from_revision": expected_revision})
        return self.get_batch(batch_id)

    def _idempotent_response(self, scope: str, key: str, request_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT request_sha256,response_json FROM idempotency_keys WHERE scope=? AND key=?",
            (scope, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_digest:
            raise Conflict("同一幂等键对应了不同请求内容")
        return json.loads(row["response_json"])

    def import_observations(
        self,
        actor_id: str,
        batch_id: str,
        idempotency_key: str,
        raw_rows: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        self._require(actor_id, "observation.import")
        rows = tuple(raw_rows)
        if not rows:
            raise ValidationFailed("观测数组不能为空")
        request_digest = content_digest(rows)
        scope = f"observations:{batch_id}"
        existing = self._idempotent_response(scope, idempotency_key, request_digest)
        if existing is not None:
            return existing
        batch = self.get_batch(batch_id)
        if batch["state"] != "running":
            raise InvalidState("只有运行中的批次可以导入观测")
        protocol, _ = self._protocol(batch["protocol_id"], batch["protocol_version"])
        parsed: list[Observation] = []
        for raw in rows:
            try:
                item = Observation.from_dict(raw, protocol)
            except ValidationError as exc:
                raise ValidationFailed(str(exc)) from exc
            if item.robot_id != self.connection.execute(
                "SELECT robot_id FROM builds WHERE build_id=?", (batch["build_id"],)
            ).fetchone()["robot_id"]:
                raise ValidationFailed("观测机器人与批次构建不一致")
            parsed.append(item)
        response = {"batch_id": batch_id, "inserted": len(parsed), "request_sha256": request_digest}
        try:
            with transaction(self.connection, immediate=True):
                for item, raw in zip(parsed, rows):
                    self.connection.execute(
                        "INSERT INTO observations(batch_id,source_batch,source_row,robot_id,stratum_key,observed_at," 
                        "metrics_json,content_sha256,imported_by,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            batch_id,
                            item.source_batch,
                            item.source_row,
                            item.robot_id,
                            item.stratum_key,
                            item.observed_at,
                            canonical_json({key: format(value, "f") for key, value in item.metrics.items()}),
                            content_digest([raw]),
                            actor_id,
                            self._now(),
                        ),
                    )
                self.connection.execute(
                    "INSERT INTO idempotency_keys(scope,key,request_sha256,response_json,created_at) VALUES(?,?,?,?,?)",
                    (scope, idempotency_key, request_digest, canonical_json(response), self._now()),
                )
                self._audit("batch", batch_id, "observations.imported", actor_id, response)
        except sqlite3.IntegrityError as exc:
            raise Conflict("来源行重复或幂等键并发冲突") from exc
        return response

    def request_exclusion(self, actor_id: str, observation_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.request")
        observation = self.connection.execute(
            "SELECT observation_id,batch_id FROM observations WHERE observation_id=?", (observation_id,)
        ).fetchone()
        if observation is None:
            raise NotFound("观测不存在")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO exclusion_requests(observation_id,status,reason,requested_by,requested_at) "
                    "VALUES(?,?,?,?,?)",
                    (observation_id, "pending", reason, actor_id, self._now()),
                )
                exclusion_id = cursor.lastrowid
                self._audit("observation", str(observation_id), "exclusion.requested", actor_id, {"reason": reason})
        except sqlite3.IntegrityError as exc:
            raise Conflict("该观测已有待处理或生效排除") from exc
        return {"exclusion_id": exclusion_id, "status": "pending"}

    def review_exclusion(
        self, actor_id: str, exclusion_id: int, approve: bool, note: str
    ) -> dict[str, Any]:
        self._require(actor_id, "exclusion.review")
        row = self.connection.execute(
            "SELECT * FROM exclusion_requests WHERE exclusion_id=?", (exclusion_id,)
        ).fetchone()
        if row is None:
            raise NotFound("排除申请不存在")
        if row["status"] != "pending":
            raise InvalidState("排除申请已经处理")
        if row["requested_by"] == actor_id:
            raise Forbidden("申请人不能复核自己的排除申请")
        status = "approved" if approve else "rejected"
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE exclusion_requests SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE exclusion_id=? AND status='pending'",
                (status, actor_id, self._now(), note, exclusion_id),
            )
            self._audit("exclusion", str(exclusion_id), f"exclusion.{status}", actor_id, {"note": note})
        return {"exclusion_id": exclusion_id, "status": status}

    def revoke_exclusion(self, actor_id: str, exclusion_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.revoke")
        row = self.connection.execute(
            "SELECT e.*,o.batch_id FROM exclusion_requests e "
            "JOIN observations o ON o.observation_id=e.observation_id WHERE e.exclusion_id=?",
            (exclusion_id,),
        ).fetchone()
        if row is None:
            raise NotFound("排除记录不存在")
        if row["status"] != "approved":
            raise InvalidState("只有已批准的排除可以撤销")
        if row["requested_by"] != actor_id:
            raise Forbidden("只有原申请人可以撤销排除")
        batch = self.get_batch(row["batch_id"])
        if batch["state"] != "running":
            raise InvalidState("批次封存后不能改变排除状态")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE exclusion_requests SET status='revoked',review_note=?,reviewed_at=? "
                "WHERE exclusion_id=? AND status='approved'",
                (reason, self._now(), exclusion_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("排除状态已变化")
            self._audit(
                "observation",
                str(row["observation_id"]),
                "exclusion.revoked",
                actor_id,
                {"exclusion_id": exclusion_id, "reason": reason},
            )
        return {"exclusion_id": exclusion_id, "status": "revoked"}

    def seal_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.seal")
        with transaction(self.connection, immediate=True):
            pending = self.connection.execute(
                "SELECT count(*) FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
                "WHERE o.batch_id=? AND e.status='pending'", (batch_id,)
            ).fetchone()[0]
            if pending:
                raise InvalidState("仍有待复核的排除申请")
            cursor = self.connection.execute(
                "UPDATE batches SET state='sealed',revision=revision+1,sealed_at=? "
                "WHERE batch_id=? AND state='running' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次状态或版本已变化")
            new_revision = expected_revision + 1
            now = self._now()
            self.connection.execute(
                "INSERT INTO analysis_jobs(batch_id,batch_revision,state,available_at,created_at,updated_at) "
                "VALUES(?,?, 'queued', ?,?,?)",
                (batch_id, new_revision, now, now, now),
            )
            self._audit("batch", batch_id, "batch.sealed", actor_id, {"revision": new_revision})
        return self.get_batch(batch_id)

    def claim_job(self, worker_id: str, lease_seconds: int = 60) -> dict[str, Any] | None:
        if lease_seconds <= 0:
            raise ValidationFailed("租约时长必须大于零")
        now = self._now()
        expires = isoformat(self.clock.now() + timedelta(seconds=lease_seconds))
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT job_id FROM analysis_jobs WHERE "
                "(state='queued' AND available_at<=?) OR (state='leased' AND lease_expires_at<=?) "
                "ORDER BY available_at,job_id LIMIT 1",
                (now, now),
            ).fetchone()
            if row is None:
                return None
            self.connection.execute(
                "UPDATE analysis_jobs SET state='leased',attempts=attempts+1,lease_owner=?,lease_expires_at=?,updated_at=? "
                "WHERE job_id=?",
                (worker_id, expires, now, row["job_id"]),
            )
            claimed = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (row["job_id"],)).fetchone()
        return dict(claimed)

    def _analysis_observations(self, batch_id: str, protocol: Protocol) -> tuple[Observation, ...]:
        rows = self.connection.execute(
            "SELECT o.*,e.reason AS excluded_reason FROM observations o "
            "LEFT JOIN exclusion_requests e ON e.observation_id=o.observation_id AND e.status='approved' "
            "WHERE o.batch_id=? ORDER BY o.observation_id",
            (batch_id,),
        ).fetchall()
        items: list[Observation] = []
        for row in rows:
            metrics = json.loads(row["metrics_json"])
            items.append(Observation(
                source_batch=row["source_batch"],
                source_row=row["source_row"],
                robot_id=row["robot_id"],
                protocol_id=protocol.protocol_id,
                protocol_version=protocol.version,
                stratum_key=row["stratum_key"],
                observed_at=row["observed_at"],
                metrics={key: Decimal(str(value)) for key, value in metrics.items()},
                excluded_reason=row["excluded_reason"],
            ))
        return tuple(items)

    def complete_job(self, worker_id: str, job_id: int, statistician_id: str) -> dict[str, Any]:
        self._require(statistician_id, "analysis.run")
        job = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)).fetchone()
        if job is None:
            raise NotFound("分析任务不存在")
        if job["state"] != "leased" or job["lease_owner"] != worker_id:
            raise InvalidState("任务未由当前工作进程持有")
        if job["lease_expires_at"] <= self._now():
            raise InvalidState("任务租约已经过期")
        batch = self.get_batch(job["batch_id"])
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        observations = self._analysis_observations(batch["batch_id"], protocol)
        snapshot_rows = [
            {
                "source_batch": item.source_batch,
                "source_row": item.source_row,
                "stratum": item.stratum_key,
                "metrics": {key: format(value, "f") for key, value in item.metrics.items()},
                "excluded_reason": item.excluded_reason,
            }
            for item in observations
        ]
        input_digest = content_digest(snapshot_rows)
        result = analyze(protocol, observations)
        with transaction(self.connection, immediate=True):
            existing = self.connection.execute(
                "SELECT analysis_id,result_json FROM analyses WHERE batch_id=? AND batch_revision=? AND input_sha256=?",
                (batch["batch_id"], job["batch_revision"], input_digest),
            ).fetchone()
            if existing is None:
                cursor = self.connection.execute(
                    "INSERT INTO analyses(batch_id,batch_revision,protocol_sha256,input_sha256,algorithm_version,seed," 
                    "result_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        batch["batch_id"], job["batch_revision"], protocol_digest, input_digest,
                        ALGORITHM_VERSION, protocol.seed, canonical_json(result), statistician_id, self._now(),
                    ),
                )
                analysis_id = cursor.lastrowid
            else:
                analysis_id = existing["analysis_id"]
                result = json.loads(existing["result_json"])
            self.connection.execute(
                "UPDATE analysis_jobs SET state='succeeded',lease_owner=NULL,lease_expires_at=NULL,updated_at=? "
                "WHERE job_id=? AND state='leased' AND lease_owner=?",
                (self._now(), job_id, worker_id),
            )
            self.connection.execute(
                "UPDATE batches SET state='analyzed' WHERE batch_id=? AND state IN ('sealed','analyzing')",
                (batch["batch_id"],),
            )
            self._audit(
                "batch",
                batch["batch_id"],
                "analysis.completed",
                statistician_id,
                {"analysis_id": analysis_id, "input_sha256": input_digest},
            )
        return {"analysis_id": analysis_id, "input_sha256": input_digest, "result": result}

    def fail_job(self, worker_id: str, job_id: int, error: str, retry_seconds: int = 0) -> dict[str, Any]:
        available = isoformat(self.clock.now() + timedelta(seconds=retry_seconds))
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE analysis_jobs SET state='queued',available_at=?,lease_owner=NULL,lease_expires_at=NULL," 
                "last_error=?,updated_at=? WHERE job_id=? AND state='leased' AND lease_owner=?",
                (available, error[:1000], self._now(), job_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("任务未由当前工作进程持有")
        return {"job_id": job_id, "state": "queued", "available_at": available}

    def decide(
        self, actor_id: str, batch_id: str, analysis_id: int, decision: str, reason: str
    ) -> dict[str, Any]:
        self._require(actor_id, "decision.write")
        if decision not in {"needs_more_data", "approved", "rejected"}:
            raise ValidationFailed("未知准入决定")
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE analysis_id=? AND batch_id=?", (analysis_id, batch_id)
        ).fetchone()
        if analysis_row is None:
            raise NotFound("分析版本不存在")
        if analysis_row["created_by"] == actor_id:
            raise Forbidden("统计负责人不能批准自己的分析")
        batch = self.get_batch(batch_id)
        if batch["state"] != "analyzed" or batch["revision"] != analysis_row["batch_revision"]:
            raise InvalidState("分析不是批次当前可审批版本")
        expires_at = (
            isoformat(self.clock.now() + self.appeal_window)
            if self.appeal_window is not None
            else None
        )
        decision_id: int | None = None
        try:
            with transaction(self.connection, immediate=True):
                # 竞态敏感的守卫必须在写事务内再次读取，才能挡住并发提交的申诉或重分析。
                if self.connection.execute(
                    "SELECT 1 FROM batches WHERE reanalysis_of_batch=? LIMIT 1", (batch_id,)
                ).fetchone() is not None:
                    raise InvalidState("该批次修订已被后续修订取代，不能再形成决定")
                if self.connection.execute(
                    "SELECT 1 FROM decisions WHERE batch_id=? AND status != 'active' LIMIT 1",
                    (batch_id,),
                ).fetchone() is not None:
                    raise InvalidState("该批次已有被撤销或被取代的决定，不能在原修订上再次决定")
                if self.connection.execute(
                    "SELECT 1 FROM appeals WHERE batch_id=? AND status='pending'", (batch_id,)
                ).fetchone() is not None:
                    raise InvalidState("存在待审申诉，不能在复议结束前形成新决定")
                cursor = self.connection.execute(
                    "INSERT INTO decisions(batch_id,analysis_id,decision,reason,decided_by,decided_at,expires_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (batch_id, analysis_id, decision, reason, actor_id, self._now(), expires_at),
                )
                decision_id = cursor.lastrowid
                self.connection.execute("UPDATE batches SET state='decided' WHERE batch_id=?", (batch_id,))
                # 新修订形成决定后，回填修订链上各“被取代”决定的取代关系与时间。
                ancestor = batch["reanalysis_of_batch"]
                while ancestor is not None:
                    self.connection.execute(
                        "UPDATE decisions SET superseded_by_decision_id=?,superseded_at=COALESCE(superseded_at,?) "
                        "WHERE batch_id=? AND status='superseded' AND superseded_by_decision_id IS NULL",
                        (decision_id, self._now(), ancestor),
                    )
                    ancestor = self.get_batch(ancestor)["reanalysis_of_batch"]
                self._audit(
                    "batch",
                    batch_id,
                    "decision.recorded",
                    actor_id,
                    {"decision_id": decision_id, "analysis_id": analysis_id, "decision": decision},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该批次已有当前有效决定或该分析版本已经形成决定") from exc
        return {"batch_id": batch_id, "analysis_id": analysis_id, "decision": decision,
                "decision_id": decision_id}

    def submit_appeal(
        self, actor_id: str, batch_id: str, decision_id: int, evidence_summary: str
    ) -> dict[str, Any]:
        """批次所属操作方对一份当前有效决定提交一次带证据摘要的申诉。"""

        self._require(actor_id, "appeal.submit")
        summary = evidence_summary.strip() if isinstance(evidence_summary, str) else ""
        if not summary:
            raise ValidationFailed("证据摘要不能为空")
        batch = self.get_batch(batch_id)
        if batch["created_by"] != actor_id:
            raise Forbidden("只有批次所属操作方可以提交申诉")
        decision_row = self.connection.execute(
            "SELECT * FROM decisions WHERE decision_id=? AND batch_id=?", (decision_id, batch_id)
        ).fetchone()
        if decision_row is None:
            raise NotFound("决定不存在或不属于该批次")
        if decision_row["status"] != "active":
            raise InvalidState("只能对当前有效决定申诉")
        if (
            decision_row["expires_at"] is not None
            and decision_row["expires_at"] <= self._now()
        ):
            raise InvalidState("决定已超过申诉期限，不能再申诉")
        try:
            with transaction(self.connection, immediate=True):
                # 条件插入：决定仍有效且未过申诉窗口才允许；并发下只有一个事务能插入待审申诉。
                now = self._now()
                cursor = self.connection.execute(
                    "INSERT INTO appeals(decision_id,batch_id,evidence_summary,requested_by,requested_at,status) "
                    "SELECT ?,?,?,?,?,'pending' "
                    "WHERE EXISTS (SELECT 1 FROM decisions WHERE decision_id=? AND status='active' "
                    "              AND (expires_at IS NULL OR expires_at > ?)) "
                    "AND NOT EXISTS (SELECT 1 FROM appeals WHERE decision_id=?) "
                    "AND NOT EXISTS (SELECT 1 FROM appeals WHERE batch_id=? AND status='pending')",
                    (
                        decision_id, batch_id, summary, actor_id, now,
                        decision_id, now, decision_id, batch_id,
                    ),
                )
                if cursor.rowcount != 1:
                    current = self.connection.execute(
                        "SELECT status,expires_at FROM decisions WHERE decision_id=?", (decision_id,)
                    ).fetchone()
                    if current is None or current["status"] != "active":
                        raise InvalidState("只能对当前有效决定申诉")
                    if current["expires_at"] is not None and current["expires_at"] <= now:
                        raise InvalidState("决定已超过申诉期限，不能再申诉")
                    raise Conflict("该决定已有申诉或批次存在待审申诉")
                appeal_id = cursor.lastrowid
                self._audit(
                    "batch",
                    batch_id,
                    "appeal.submitted",
                    actor_id,
                    {"appeal_id": appeal_id, "decision_id": decision_id, "evidence_summary": summary},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该决定已有申诉或批次存在待审申诉") from exc
        return {"appeal_id": appeal_id, "decision_id": decision_id, "status": "pending"}

    def review_appeal(
        self, actor_id: str, appeal_id: int, outcome: str, note: str
    ) -> dict[str, Any]:
        """另一名审批人对申诉作出维持、撤销或要求重新分析的裁决。"""

        self._require(actor_id, "appeal.review")
        if outcome not in {"uphold", "revoke", "reanalyze"}:
            raise ValidationFailed("复议结果必须是 uphold、revoke 或 reanalyze")
        review_note = note.strip() if isinstance(note, str) else ""
        if outcome == "reanalyze" and not review_note:
            raise ValidationFailed("要求重新分析必须说明明确的排除变更或补充材料")
        appeal_status = {"uphold": "upheld", "revoke": "revoked", "reanalyze": "reanalyze"}[outcome]
        appeal_row = self.connection.execute(
            "SELECT * FROM appeals WHERE appeal_id=?", (appeal_id,)
        ).fetchone()
        if appeal_row is None:
            raise NotFound("申诉不存在")
        if appeal_row["status"] != "pending":
            raise InvalidState("申诉已经裁决")
        decision_row = self.connection.execute(
            "SELECT * FROM decisions WHERE decision_id=?", (appeal_row["decision_id"],)
        ).fetchone()
        if decision_row["decided_by"] == actor_id:
            raise Forbidden("原决定人不能担任复议人")
        batch_id = appeal_row["batch_id"]
        now = self._now()
        reanalysis_batch_id: str | None = None
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE appeals SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE appeal_id=? AND status='pending'",
                (appeal_status, actor_id, now, review_note, appeal_id),
            )
            if cursor.rowcount != 1:
                # 并发下另一名复议人已经裁决：阻止双重裁决。
                raise Conflict("申诉已被其他复议人裁决")
            if outcome in {"revoke", "reanalyze"}:
                updated = self.connection.execute(
                    "UPDATE decisions SET status='revoked',revoked_by=?,revoked_at=?,revoke_reason=? "
                    "WHERE decision_id=? AND status='active'",
                    (actor_id, now, review_note, decision_row["decision_id"]),
                ) if outcome == "revoke" else self.connection.execute(
                    "UPDATE decisions SET status='superseded',superseded_at=? "
                    "WHERE decision_id=? AND status='active'",
                    (now, decision_row["decision_id"]),
                )
                if updated.rowcount != 1:
                    raise InvalidState("原决定已失效，不能完成本次裁决")
            if outcome == "reanalyze":
                reanalysis_batch_id = self._create_reanalysis_batch(
                    actor_id=actor_id,
                    source_batch_id=batch_id,
                    appeal_id=appeal_id,
                    reason=review_note,
                    now=now,
                )
                self.connection.execute(
                    "UPDATE appeals SET reanalysis_batch_id=? WHERE appeal_id=?",
                    (reanalysis_batch_id, appeal_id),
                )
            self._audit(
                "batch",
                batch_id,
                f"appeal.{appeal_status}",
                actor_id,
                {
                    "appeal_id": appeal_id,
                    "decision_id": decision_row["decision_id"],
                    "note": review_note,
                    **({"reanalysis_batch_id": reanalysis_batch_id} if reanalysis_batch_id else {}),
                },
            )
            if reanalysis_batch_id is not None:
                self._audit(
                    "batch",
                    reanalysis_batch_id,
                    "batch.reanalysis_created",
                    actor_id,
                    {
                        "source_batch_id": batch_id,
                        "appeal_id": appeal_id,
                        "reason": review_note,
                    },
                )
        return {
            "appeal_id": appeal_id,
            "outcome": outcome,
            "status": appeal_status,
            "reanalysis_batch_id": reanalysis_batch_id,
        }

    def _create_reanalysis_batch(
        self,
        *,
        actor_id: str,
        source_batch_id: str,
        appeal_id: int,
        reason: str,
        now: str,
    ) -> str:
        """复制原批次数据生成新的批次修订，作为补充材料与重分析的载体。"""

        source = self.get_batch(source_batch_id)
        # 沿修订链找到根批次；新修订编号为链上批次总数（根为 1，首次重分析即 #r1）。
        root = source
        chain_length = 1
        while root["reanalysis_of_batch"] is not None:
            root = self.get_batch(root["reanalysis_of_batch"])
            chain_length += 1
        suffix = chain_length
        while True:
            new_batch_id = f"{root['batch_id']}#r{suffix}"
            if self.connection.execute(
                "SELECT 1 FROM batches WHERE batch_id=?", (new_batch_id,)
            ).fetchone() is None:
                break
            suffix += 1
        self.connection.execute(
            "INSERT INTO batches(batch_id,protocol_id,protocol_version,build_id,state,revision,"
            "created_by,created_at,started_at,reanalysis_of_batch,reanalysis_reason,reanalysis_appeal_id) "
            "VALUES(?,?,?,?, 'running', 1,?,?,?,?,?,?)",
            (
                new_batch_id,
                source["protocol_id"],
                source["protocol_version"],
                source["build_id"],
                source["created_by"],
                now,
                now,
                source_batch_id,
                reason,
                appeal_id,
            ),
        )
        observations = self.connection.execute(
            "SELECT * FROM observations WHERE batch_id=? ORDER BY observation_id",
            (source_batch_id,),
        ).fetchall()
        old_to_new: dict[int, int] = {}
        for row in observations:
            cursor = self.connection.execute(
                "INSERT INTO observations(batch_id,source_batch,source_row,robot_id,stratum_key,observed_at,"
                "metrics_json,content_sha256,imported_by,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    new_batch_id,
                    row["source_batch"],
                    row["source_row"],
                    row["robot_id"],
                    row["stratum_key"],
                    row["observed_at"],
                    row["metrics_json"],
                    row["content_sha256"],
                    row["imported_by"],
                    row["imported_at"],
                ),
            )
            old_to_new[row["observation_id"]] = cursor.lastrowid
        approved = self.connection.execute(
            "SELECT * FROM exclusion_requests WHERE observation_id IN (%s) AND status='approved'"
            % ",".join("?" * len(observations)),
            [row["observation_id"] for row in observations],
        ).fetchall() if observations else []
        for exclusion in approved:
            self.connection.execute(
                "INSERT INTO exclusion_requests(observation_id,status,reason,requested_by,requested_at,"
                "reviewed_by,reviewed_at,review_note) VALUES(?, 'approved', ?,?,?,?,?,?)",
                (
                    old_to_new[exclusion["observation_id"]],
                    exclusion["reason"],
                    exclusion["requested_by"],
                    exclusion["requested_at"],
                    exclusion["reviewed_by"],
                    exclusion["reviewed_at"],
                    exclusion["review_note"],
                ),
            )
        self._audit(
            "batch",
            source_batch_id,
            "batch.revision_copied",
            actor_id,
            {
                "new_batch_id": new_batch_id,
                "observations_copied": len(observations),
                "exclusions_copied": len(approved),
            },
        )
        return new_batch_id

    def _lineage(self, batch_id: str) -> list[sqlite3.Row]:
        """返回根批次到最新修订（含被查询批次）的完整线性修订链。"""

        ancestors: list[sqlite3.Row] = []
        current = self.get_batch(batch_id)
        while True:
            ancestors.append(current)
            parent_id = current["reanalysis_of_batch"]
            if parent_id is None:
                break
            current = self.get_batch(parent_id)
        chain = list(reversed(ancestors))
        # 重分析只能发生在当前有效决定上，因此修订链为线性；沿子修订继续向下。
        while True:
            child = self.connection.execute(
                "SELECT * FROM batches WHERE reanalysis_of_batch=? "
                "ORDER BY rowid DESC LIMIT 1",
                (chain[-1]["batch_id"],),
            ).fetchone()
            if child is None:
                break
            chain.append(child)
        return chain

    def report(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        user = self._user(actor_id)
        if user["role"] not in {"statistician", "approver", "auditor"}:
            raise Forbidden("当前角色不能读取完整报告")
        batch = self.get_batch(batch_id)
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        chain = self._lineage(batch_id)
        chain_ids = [item["batch_id"] for item in chain]
        placeholders = ",".join("?" * len(chain_ids))

        analyses = self.connection.execute(
            f"SELECT * FROM analyses WHERE batch_id IN ({placeholders}) ORDER BY analysis_id",
            chain_ids,
        ).fetchall()
        analysis_by_id = {row["analysis_id"]: row for row in analyses}
        decisions = self.connection.execute(
            f"SELECT * FROM decisions WHERE batch_id IN ({placeholders}) ORDER BY decision_id",
            chain_ids,
        ).fetchall()
        decisions_by_id = {row["decision_id"]: row for row in decisions}
        appeals = self.connection.execute(
            f"SELECT * FROM appeals WHERE batch_id IN ({placeholders}) ORDER BY appeal_id",
            chain_ids,
        ).fetchall()
        appeals_by_id = {row["appeal_id"]: row for row in appeals}
        exclusions = self.connection.execute(
            "SELECT e.exclusion_id,e.observation_id,e.status,e.reason,e.requested_by,e.reviewed_by,o.batch_id "
            "FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
            f"WHERE o.batch_id IN ({placeholders}) ORDER BY e.exclusion_id",
            chain_ids,
        ).fetchall()
        events = self.connection.execute(
            "SELECT event_id,event_type,actor_id,payload_json,created_at,entity_id AS batch_id FROM audit_events "
            f"WHERE entity_type='batch' AND entity_id IN ({placeholders}) ORDER BY event_id",
            chain_ids,
        ).fetchall()

        def analysis_brief(row: sqlite3.Row) -> dict[str, Any]:
            result = json.loads(row["result_json"])
            return {
                "analysis_id": row["analysis_id"],
                "batch_id": row["batch_id"],
                "batch_revision": row["batch_revision"],
                "input_sha256": row["input_sha256"],
                "algorithm_version": row["algorithm_version"],
                "created_by": row["created_by"],
                "created_at": row["created_at"],
                "conclusion": result.get("conclusion"),
                "result": result,
            }

        def decision_brief(row: sqlite3.Row) -> dict[str, Any]:
            data = dict(row)
            analysis_row = analysis_by_id.get(row["analysis_id"])
            data["analysis"] = None if analysis_row is None else analysis_brief(analysis_row)
            return data

        # 按时间（审计事件序号）合并原决定、申诉、复议与新分析，形成可解释的责任链。
        # 所有关键状态迁移都在同一事务写入审计事件，因此 event_id 给出严格因果顺序，
        # 即使时钟分辨率不足或被冻结也不会乱序。
        timeline: list[dict[str, Any]] = []
        for event in events:
            payload = json.loads(event["payload_json"])
            entry: dict[str, Any] | None = None
            if event["event_type"] == "analysis.completed":
                row = analysis_by_id.get(payload.get("analysis_id"))
                if row is not None:
                    entry = {"kind": "analysis", "batch_id": row["batch_id"],
                             "analysis": analysis_brief(row)}
            elif event["event_type"] == "decision.recorded":
                row = decisions_by_id.get(payload.get("decision_id"))
                if row is not None:
                    entry = {"kind": "decision", "batch_id": row["batch_id"],
                             "decision": decision_brief(row)}
            elif event["event_type"] == "appeal.submitted":
                row = appeals_by_id.get(payload.get("appeal_id"))
                if row is not None:
                    entry = {"kind": "appeal", "batch_id": row["batch_id"], "appeal": dict(row)}
            elif event["event_type"] in {
                "appeal.upheld", "appeal.revoked", "appeal.reanalyze",
            }:
                row = appeals_by_id.get(payload.get("appeal_id"))
                if row is not None:
                    entry = {"kind": "appeal_review", "batch_id": row["batch_id"],
                             "appeal": dict(row), "outcome": event["event_type"].split(".", 1)[1]}
            elif event["event_type"] == "batch.reanalysis_created":
                entry = {"kind": "revision", "batch_id": event["batch_id"], "change": payload}
            if entry is not None:
                entry["at"] = event["created_at"]
                timeline.append(entry)

        # 当前有效结论：沿修订链从新到旧找到第一份仍然有效的决定。
        current_decision = next(
            (row for row in reversed(decisions) if row["status"] == "active"), None
        )
        superseded = [decision_brief(row) for row in decisions if row["status"] != "active"]
        current = None
        if current_decision is not None:
            current_analysis = analysis_by_id.get(current_decision["analysis_id"])
            current = {
                "decision": decision_brief(current_decision),
                "analysis": None if current_analysis is None else analysis_brief(current_analysis),
                "supersedes": superseded,
            }
        analysis_row = analyses[-1] if analyses else None
        decision_row = next(
            (row for row in reversed(decisions) if row["batch_id"] == batch_id), None
        )
        return {
            "batch": batch,
            "lineage": chain_ids,
            "protocol": {
                "protocol_id": protocol.protocol_id,
                "version": protocol.version,
                "sha256": protocol_digest,
                "seed": protocol.seed,
                "bootstrap_samples": protocol.bootstrap_samples,
            },
            "analysis": None if analysis_row is None else analysis_brief(analysis_row),
            "decision": None if decision_row is None else decision_brief(decision_row),
            "current_effective": current,
            "analyses": [analysis_brief(row) for row in analyses],
            "decisions": [decision_brief(row) for row in decisions],
            "appeals": [dict(row) for row in appeals],
            "exclusions": [dict(row) for row in exclusions],
            "timeline": timeline,
            "events": [dict(row) | {"payload": json.loads(row["payload_json"])} for row in events],
        }
