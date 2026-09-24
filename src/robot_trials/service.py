"""统计准入服务的领域用例。"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .analysis import ALGORITHM_VERSION, analyze
from .clock import SystemClock, isoformat
from .contracts import Observation, Protocol, ValidationError
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


ROLE_PERMISSIONS = {
    "operator": {
        "catalog.write", "batch.create", "batch.start", "observation.import",
        "exclusion.request", "exclusion.revoke", "appeal.submit",
    },
    "statistician": {"protocol.publish", "batch.seal", "exclusion.review", "analysis.run"},
    "approver": {"decision.write", "appeal.review"},
    "auditor": {"report.read", "audit.read"},
}

APPEAL_WINDOW = timedelta(days=7)

_KIND_ORDER = {"decision": 0, "appeal": 1, "review": 2, "analysis": 3}


class TrialService:
    """在单个 SQLite 连接上提供全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
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
        if batch["state"] not in {"running", "reanalyzing"}:
            raise InvalidState("只有运行中或复议重分析中的批次可以导入观测")
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
        if batch["state"] not in {"running", "reanalyzing"}:
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
            now = self._now()
            cursor = self.connection.execute(
                "UPDATE batches SET state='sealed',revision=revision+1,sealed_at=? "
                "WHERE batch_id=? AND state='running' AND revision=?",
                (now, batch_id, expected_revision),
            )
            if cursor.rowcount == 1:
                new_revision = expected_revision + 1
                self.connection.execute(
                    "INSERT INTO analysis_jobs(batch_id,batch_revision,state,available_at,created_at,updated_at) "
                    "VALUES(?,?, 'queued', ?,?,?)",
                    (batch_id, new_revision, now, now, now),
                )
                self._audit("batch", batch_id, "batch.sealed", actor_id, {"revision": new_revision})
            else:
                cursor = self.connection.execute(
                    "UPDATE batches SET state='sealed',sealed_at=? "
                    "WHERE batch_id=? AND state='reanalyzing' AND revision=?",
                    (now, batch_id, expected_revision),
                )
                if cursor.rowcount != 1:
                    raise InvalidState("批次状态或版本已变化")
                job = self.connection.execute(
                    "UPDATE analysis_jobs SET state='queued',available_at=?,updated_at=? "
                    "WHERE batch_id=? AND batch_revision=? AND state='waiting'",
                    (now, now, batch_id, expected_revision),
                )
                if job.rowcount != 1:
                    raise InvalidState("重分析任务缺失或已被领取")
                self._audit(
                    "batch", batch_id, "batch.sealed", actor_id,
                    {"revision": expected_revision, "reanalysis": True},
                )
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
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO decisions(batch_id,analysis_id,decision,reason,decided_by,decided_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (batch_id, analysis_id, decision, reason, actor_id, self._now()),
                )
                new_decision_id = cursor.lastrowid
                self.connection.execute(
                    "UPDATE decisions SET superseded_by_appeal_id="
                    "(SELECT da.appeal_id FROM decision_appeals da "
                    "WHERE da.decision_id=decisions.decision_id AND da.status='reanalyze' "
                    "ORDER BY da.appeal_id DESC LIMIT 1) "
                    "WHERE batch_id=? AND decision_id<>? AND superseded_by_appeal_id IS NULL",
                    (batch_id, new_decision_id),
                )
                self.connection.execute("UPDATE batches SET state='decided' WHERE batch_id=?", (batch_id,))
                self._audit(
                    "batch",
                    batch_id,
                    "decision.recorded",
                    actor_id,
                    {"decision_id": new_decision_id, "analysis_id": analysis_id, "decision": decision},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该分析版本已经形成决定") from exc
        return {"batch_id": batch_id, "analysis_id": analysis_id, "decision": decision}

    def submit_appeal(
        self, actor_id: str, decision_id: int, evidence_summary: str
    ) -> dict[str, Any]:
        self._require(actor_id, "appeal.submit")
        if not evidence_summary.strip():
            raise ValidationFailed("证据摘要不能为空")
        decision = self.connection.execute(
            "SELECT * FROM decisions WHERE decision_id=?", (decision_id,)
        ).fetchone()
        if decision is None:
            raise NotFound("决定不存在")
        batch = self.get_batch(decision["batch_id"])
        if batch["created_by"] != actor_id:
            raise Forbidden("只有批次所属操作方可以申诉该批次的决定")
        if self.clock.now() - _parse_ts(decision["decided_at"]) > APPEAL_WINDOW:
            raise InvalidState("超过申诉期限，不能对过期决定提出申诉")
        try:
            with transaction(self.connection, immediate=True):
                existing = self.connection.execute(
                    "SELECT status FROM decision_appeals WHERE decision_id=? ORDER BY appeal_id LIMIT 1",
                    (decision_id,),
                ).fetchone()
                if existing is not None:
                    if existing["status"] == "pending":
                        raise Conflict("该决定已有待审申诉")
                    raise Conflict("该决定的申诉已经裁决，不能再次申诉")
                cursor = self.connection.execute(
                    "INSERT INTO decision_appeals(decision_id,batch_id,evidence_summary,appealed_by,appealed_at,status) "
                    "VALUES(?,?,?,?,?, 'pending')",
                    (decision_id, decision["batch_id"], evidence_summary.strip(), actor_id, self._now()),
                )
                appeal_id = cursor.lastrowid
                self._audit(
                    "decision",
                    str(decision_id),
                    "appeal.submitted",
                    actor_id,
                    {"appeal_id": appeal_id, "batch_id": decision["batch_id"]},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该决定已有待审申诉") from exc
        return {"appeal_id": appeal_id, "decision_id": decision_id, "status": "pending"}

    def review_appeal(
        self, actor_id: str, appeal_id: int, action: str, note: str, reanalysis_directive: str = ""
    ) -> dict[str, Any]:
        self._require(actor_id, "appeal.review")
        if action not in {"uphold", "revoke", "reanalyze"}:
            raise ValidationFailed("未知复议动作")
        if not note.strip():
            raise ValidationFailed("复议意见不能为空")
        directive = reanalysis_directive.strip()
        if action == "reanalyze" and not directive:
            raise ValidationFailed("要求重新分析必须给出明确的排除变更或补充材料要求")
        appeal = self.connection.execute(
            "SELECT * FROM decision_appeals WHERE appeal_id=?", (appeal_id,)
        ).fetchone()
        if appeal is None:
            raise NotFound("申诉不存在")
        if appeal["status"] != "pending":
            raise InvalidState("申诉已经裁决")
        decision = self.connection.execute(
            "SELECT * FROM decisions WHERE decision_id=?", (appeal["decision_id"],)
        ).fetchone()
        if decision["decided_by"] == actor_id:
            raise Forbidden("原决定人不得担任复议人")
        status = {"uphold": "upheld", "revoke": "revoked", "reanalyze": "reanalyze"}[action]
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE decision_appeals SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE appeal_id=? AND status='pending'",
                (status, actor_id, self._now(), note.strip(), appeal_id),
            )
            if cursor.rowcount != 1:
                raise Conflict("申诉已被并发裁决")
            reanalysis_job_id: int | None = None
            reanalysis_revision: int | None = None
            if action == "revoke":
                self.connection.execute(
                    "UPDATE batches SET state='decided' WHERE batch_id=?",
                    (appeal["batch_id"],),
                )
            if action == "reanalyze":
                batch = self.get_batch(appeal["batch_id"])
                new_revision = batch["revision"] + 1
                now = self._now()
                job_cursor = self.connection.execute(
                    "INSERT INTO analysis_jobs(batch_id,batch_revision,state,available_at,created_at,updated_at) "
                    "VALUES(?,?, 'waiting', ?,?,?)",
                    (appeal["batch_id"], new_revision, now, now, now),
                )
                reanalysis_job_id = job_cursor.lastrowid
                reanalysis_revision = new_revision
                self.connection.execute(
                    "UPDATE batches SET state='reanalyzing',revision=? WHERE batch_id=?",
                    (new_revision, appeal["batch_id"]),
                )
                self.connection.execute(
                    "UPDATE decision_appeals SET reanalysis_job_id=?,reanalysis_batch_revision=?,"
                    "reanalysis_directive=? WHERE appeal_id=?",
                    (reanalysis_job_id, new_revision, directive, appeal_id),
                )
                self._audit(
                    "batch",
                    appeal["batch_id"],
                    "batch.reopened",
                    actor_id,
                    {
                        "appeal_id": appeal_id,
                        "revision": new_revision,
                        "job_id": reanalysis_job_id,
                        "directive": directive,
                    },
                )
            self._audit(
                "decision",
                str(appeal["decision_id"]),
                f"appeal.{status}",
                actor_id,
                {
                    "appeal_id": appeal_id,
                    "batch_id": appeal["batch_id"],
                    **(
                        {
                            "job_id": reanalysis_job_id,
                            "revision": reanalysis_revision,
                            "directive": directive,
                        }
                        if action == "reanalyze"
                        else {}
                    ),
                },
            )
        return {
            "appeal_id": appeal_id,
            "decision_id": appeal["decision_id"],
            "status": status,
            **(
                {
                    "reanalysis_job_id": reanalysis_job_id,
                    "reanalysis_batch_revision": reanalysis_revision,
                    "reanalysis_directive": directive,
                }
                if action == "reanalyze"
                else {}
            ),
        }

    def report(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        user = self._user(actor_id)
        if user["role"] not in {"statistician", "approver", "auditor"}:
            raise Forbidden("当前角色不能读取完整报告")
        batch = self.get_batch(batch_id)
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        analyses = {
            row["analysis_id"]: row
            for row in self.connection.execute(
                "SELECT * FROM analyses WHERE batch_id=? ORDER BY analysis_id", (batch_id,)
            ).fetchall()
        }
        decisions = self.connection.execute(
            "SELECT * FROM decisions WHERE batch_id=? ORDER BY decision_id", (batch_id,)
        ).fetchall()
        appeals = self.connection.execute(
            "SELECT * FROM decision_appeals WHERE batch_id=? ORDER BY appeal_id", (batch_id,)
        ).fetchall()

        timeline: list[dict[str, Any]] = []
        for row in decisions:
            item = dict(row)
            analysis_row = analyses.get(row["analysis_id"])
            item["analysis"] = None if analysis_row is None else {
                "analysis_id": analysis_row["analysis_id"],
                "batch_revision": analysis_row["batch_revision"],
                "input_sha256": analysis_row["input_sha256"],
                "algorithm_version": analysis_row["algorithm_version"],
                "created_by": analysis_row["created_by"],
                "result": json.loads(analysis_row["result_json"]),
            }
            timeline.append({"at": row["decided_at"], "kind": "decision", "item": item})
        for row in appeals:
            timeline.append({
                "at": row["appealed_at"],
                "kind": "appeal",
                "item": {
                    "appeal_id": row["appeal_id"],
                    "decision_id": row["decision_id"],
                    "evidence_summary": row["evidence_summary"],
                    "appealed_by": row["appealed_by"],
                    "status": row["status"],
                },
            })
            if row["reviewed_at"] is not None:
                timeline.append({
                    "at": row["reviewed_at"],
                    "kind": "review",
                    "item": {
                        "appeal_id": row["appeal_id"],
                        "decision_id": row["decision_id"],
                        "outcome": row["status"],
                        "reviewed_by": row["reviewed_by"],
                        "review_note": row["review_note"],
                        **(
                            {
                                "reanalysis_job_id": row["reanalysis_job_id"],
                                "reanalysis_batch_revision": row["reanalysis_batch_revision"],
                                "reanalysis_directive": row["reanalysis_directive"],
                            }
                            if row["status"] == "reanalyze"
                            else {}
                        ),
                    },
                })
        analysis_events = [
            (json.loads(row["payload_json"]), row["created_at"])
            for row in self.connection.execute(
                "SELECT created_at,payload_json FROM audit_events "
                "WHERE entity_type='batch' AND entity_id=? AND event_type='analysis.completed' "
                "ORDER BY event_id",
                (batch_id,),
            ).fetchall()
        ]
        for payload, created_at in analysis_events:
            analysis_id = payload.get("analysis_id")
            analysis_row = analyses.get(analysis_id)
            if analysis_row is None:
                continue
            timeline.append({
                "at": created_at,
                "kind": "analysis",
                "item": {
                    "analysis_id": analysis_row["analysis_id"],
                    "batch_revision": analysis_row["batch_revision"],
                    "input_sha256": analysis_row["input_sha256"],
                    "algorithm_version": analysis_row["algorithm_version"],
                    "created_by": analysis_row["created_by"],
                    "result": json.loads(analysis_row["result_json"]),
                },
            })
        timeline.sort(key=lambda entry: (entry["at"], _KIND_ORDER[entry["kind"]]))

        decision_by_id = {row["decision_id"]: row for row in decisions}
        appeals_by_decision: dict[int, list[sqlite3.Row]] = {}
        for row in appeals:
            appeals_by_decision.setdefault(row["decision_id"], []).append(row)
        for entry in timeline:
            if entry["kind"] != "decision":
                continue
            item = entry["item"]
            item["superseded"] = item["superseded_by_appeal_id"] is not None
            appeal_row = None
            if item["superseded_by_appeal_id"] is not None:
                appeal_row = next(
                    (row for row in appeals if row["appeal_id"] == item["superseded_by_appeal_id"]),
                    None,
                )
                item["superseded_reason"] = None if appeal_row is None else appeal_row["status"]
            outcomes = [row["status"] for row in appeals_by_decision.get(item["decision_id"], [])]
            if "revoked" in outcomes:
                item["effect"] = "revoked"
            elif "reanalyze" in outcomes or item["superseded_by_appeal_id"] is not None:
                item["effect"] = "superseded_by_reanalysis"
            else:
                item["effect"] = "in_force"

        effective_decision = None
        if decisions:
            effective_decision = dict(decisions[-1])
            effective_appeal = next(
                (row for row in reversed(appeals) if row["decision_id"] == effective_decision["decision_id"]),
                None,
            )
            effective_status = "in_force"
            if effective_appeal is not None and effective_appeal["status"] in {"revoked", "reanalyze"}:
                effective_status = (
                    "revoked" if effective_appeal["status"] == "revoked" else "superseded_by_reanalysis"
                )
            effective_decision["effective_status"] = effective_status

        latest_analysis_row = None
        if analyses:
            latest_analysis_row = analyses[max(analyses)]
        effective_analysis_id = None
        if effective_decision is not None and effective_decision["effective_status"] == "in_force":
            effective_analysis_id = effective_decision["analysis_id"]
        elif (
            latest_analysis_row is not None
            and latest_analysis_row["batch_revision"] == batch["revision"]
        ):
            effective_analysis_id = latest_analysis_row["analysis_id"]

        decision_ids = [row["decision_id"] for row in decisions]
        event_rows = self.connection.execute(
            "SELECT event_type,actor_id,payload_json,created_at FROM audit_events "
            "WHERE (entity_type='batch' AND entity_id=?) "
            "OR (entity_type='decision' AND entity_id IN (SELECT value FROM json_each(?))) "
            "ORDER BY event_id",
            (batch_id, canonical_json([str(value) for value in decision_ids])),
        ).fetchall()

        exclusions = self.connection.execute(
            "SELECT e.exclusion_id,e.observation_id,e.status,e.reason,e.requested_by,e.reviewed_by "
            "FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
            "WHERE o.batch_id=? ORDER BY e.exclusion_id", (batch_id,)
        ).fetchall()
        latest_decision_row = None if not decisions else decision_by_id[effective_decision["decision_id"]]

        return {
            "batch": batch,
            "protocol": {
                "protocol_id": protocol.protocol_id,
                "version": protocol.version,
                "sha256": protocol_digest,
                "seed": protocol.seed,
                "bootstrap_samples": protocol.bootstrap_samples,
            },
            "timeline": timeline,
            "current": {
                "batch_state": batch["state"],
                "batch_revision": batch["revision"],
                "effective_decision": None if effective_decision is None else {
                    "decision_id": effective_decision["decision_id"],
                    "decision": effective_decision["decision"],
                    "effective_status": effective_decision["effective_status"],
                    "decided_by": effective_decision["decided_by"],
                    "decided_at": effective_decision["decided_at"],
                },
                "effective_analysis_id": effective_analysis_id,
            },
            "analysis": None if latest_analysis_row is None else {
                "analysis_id": latest_analysis_row["analysis_id"],
                "batch_revision": latest_analysis_row["batch_revision"],
                "input_sha256": latest_analysis_row["input_sha256"],
                "algorithm_version": latest_analysis_row["algorithm_version"],
                "created_by": latest_analysis_row["created_by"],
                "result": json.loads(latest_analysis_row["result_json"]),
            },
            "decision": None if latest_decision_row is None else dict(latest_decision_row),
            "exclusions": [dict(row) for row in exclusions],
            "events": [dict(row) | {"payload": json.loads(row["payload_json"])} for row in event_rows],
        }
