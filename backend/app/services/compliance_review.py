"""合规复查领域服务：对合规扫描发现的违规条款进行人工复查并持久化签署结论。

设计要点：
- 复查以「资产 + 合规条款 + 目标字段」为唯一签署维度，同一条款同一字段
  只认同一条有效签署，并发提交只保留先到的一次，后续提交返回冲突提示。
- 复查结论一经签署即成为该条款的有效结论，评分取数时优先于任何扫描批次
  （包括夜间才抵达的旧版补报），保证历史扫描补报不会推翻已完成的整改。
- 兼容历史已签发记录：早期复查可能没有 finding_key/目标字段 等结构化字段，
  读取时按缺省值归一化，不要求迁移旧数据。
"""
from __future__ import annotations

import threading
import time as _time
from typing import Any

from app.services.base import BaseModuleService
from app.services.compliance_scan import build_finding_key, clause_key_of
from app.store import store

# 复查通过 / 复查不通过（沿用扫描记录的中文状态词，便于取数逻辑对齐）
CONCLUSION_PASS = "复查通过"
CONCLUSION_FAIL = "复查不通过"
EFFECTIVE_REVIEW_STATUS = {"复查通过", "复查不通过"}


class ComplianceReviewService(BaseModuleService):
    MODULE = "compliance_review"
    ENTITY = "合规复查"
    OPERATION_TERM = "签署"
    LIST_FIELDS = [
        "复查编号", "目标资产", "合规条款", "目标字段", "复查结论",
        "复查人", "复查日期", "留存依据", "引用批次", "复查状态",
    ]
    REQUIRED_FIELDS = ["复查编号", "目标资产", "合规条款", "复查结论"]
    STATUS_ORDER = ["待复查", "复查通过", "复查不通过", "已撤销"]
    ACTION_RULES = {"签署通过": "复查通过", "维持违规": "复查不通过", "撤销签署": "已撤销"}
    NEGATIVE_ACTIONS = ["维持违规"]

    # 同一条款（资产+条款+字段）只允许一次有效签署，锁覆盖检查与写入两步，
    # 让并发复查在进程内串行化，避免重复签署。
    _sign_lock = threading.Lock()

    # ── 签署 ──────────────────────────────────────────────────

    def sign_review(
        self,
        asset_code: str,
        compliance_clause: str,
        conclusion: str,
        reviewer: str,
        target_field: str = "全表",
        evidence: str = "",
        ref_batch_no: str = "",
        review_date: str | None = None,
    ) -> dict[str, Any]:
        """对某资产某条款（可细化到字段）签署复查结论。

        同一条款维度已存在有效签署时拒绝重复签署，返回 ok=False 并带回
        已生效的复查号，调用方据此提示「只认同一条款一次有效签署」。
        """
        normalized = self._normalize_conclusion(conclusion)
        if normalized is None:
            return {
                "ok": False,
                "message": f"复查结论「{conclusion}」无效，仅支持复查通过/复查不通过",
                "review": None,
                "duplicate": False,
            }

        c_key = clause_key_of(compliance_clause)
        f_key = build_finding_key(compliance_clause, target_field)
        review_date = review_date or _time.strftime("%Y-%m-%d %H:%M:%S")

        with self._sign_lock:
            existing = self._find_effective_review(asset_code, f_key)
            if existing is not None:
                return {
                    "ok": False,
                    "message": (
                        f"条款「{compliance_clause}」/字段「{target_field}」已存在有效签署"
                        f"{existing.get('复查编号', '')}，同一条款只认同一次有效签署"
                    ),
                    "review": existing,
                    "duplicate": True,
                }

            review_id = store.next_id(self.MODULE)
            review = {
                "id": review_id,
                "复查编号": f"REVI-{review_id:04d}",
                "目标资产": asset_code,
                "合规条款": compliance_clause,
                "目标字段": target_field or "全表",
                "复查结论": normalized,
                "复查人": reviewer,
                "复查日期": review_date,
                "留存依据": evidence,
                "引用批次": ref_batch_no,
                "复查状态": normalized,
                "clause_key": c_key,
                "finding_key": f_key,
                "signed": True,
                "signed_at": review_date,
                "status": normalized,
                "pending": normalized != CONCLUSION_PASS,
                "abnormal": normalized == CONCLUSION_FAIL,
                "created_at": review_date,
            }
            store.rows(self.MODULE).append(review)

        store.log_change(
            self.MODULE, review_id, "合规复查签署",
            before=None,
            after=f"{normalized}: 条款{compliance_clause}/字段{target_field}",
            source="compliance_review", scope="compliance_review",
        )
        self.emit_event("compliance_review_signed", {
            "review_id": review_id,
            "asset_code": asset_code,
            "finding_key": f_key,
            "conclusion": normalized,
        })

        # 签署即刻生效：协调整改待办，通过项关闭、维持违规项保留，不必等下次评分
        from app.services.compliance_scan import ComplianceScanService
        remediation = ComplianceScanService().reconcile_remediation_issues(asset_code)
        return {
            "ok": True,
            "message": "复查结论已签署并留存",
            "review": review,
            "duplicate": False,
            "closed_issue_ids": [i.get("id") for i in remediation["closed"]],
            "open_violations": remediation["open_violations"],
        }

    def revoke_review(self, review_id: int) -> dict[str, Any] | None:
        """撤销一次签署（保留记录，不再作为有效结论）。"""
        review = self.get_entry(review_id)
        if review is None:
            return None
        old_status = review.get("status")
        review["status"] = "已撤销"
        review["复查状态"] = "已撤销"
        review["signed"] = False
        review["pending"] = False
        review["abnormal"] = False
        review["revoked_at"] = _time.strftime("%Y-%m-%d %H:%M:%S")
        store.log_change(
            self.MODULE, review_id, "撤销复查签署",
            before=old_status, after="已撤销",
            source="compliance_review", scope="compliance_review",
        )
        # 撤销后结论回退到最新扫描批次：批次仍违规则重新开待办
        from app.services.compliance_scan import ComplianceScanService
        remediation = ComplianceScanService().reconcile_remediation_issues(
            str(review.get("目标资产", ""))
        )
        review["reopened_issue_ids"] = [i.get("id") for i in remediation["opened"]]
        return review

    # ── 查询 ──────────────────────────────────────────────────

    def get_reviews_by_asset(self, asset_code: str) -> list[dict[str, Any]]:
        """资产下的全部复查记录（含已撤销，便于审计回溯）。"""
        return store.find_by_field(self.MODULE, "目标资产", asset_code)

    def get_effective_reviews(self, asset_code: str) -> list[dict[str, Any]]:
        """资产下当前仍有效的签署记录。"""
        return [
            r for r in store.rows(self.MODULE)
            if r.get("目标资产") == asset_code and self._is_effective(r)
        ]

    def get_review_for_finding(self, asset_code: str, finding_key: str) -> dict[str, Any] | None:
        """按条款维度键定位有效复查记录。"""
        return self._find_effective_review(asset_code, finding_key)

    def effective_review_map(self, asset_code: str) -> dict[str, dict[str, Any]]:
        """finding_key -> 有效复查记录，供扫描聚合与评分取数复用。"""
        return {
            self._finding_key_of(r): r
            for r in store.rows(self.MODULE)
            if r.get("目标资产") == asset_code and self._is_effective(r)
        }

    # ── 内部工具 ──────────────────────────────────────────────

    @staticmethod
    def _normalize_conclusion(conclusion: str) -> str | None:
        text = str(conclusion or "").strip()
        if text in ("复查通过", "通过", "合规", "已通过"):
            return CONCLUSION_PASS
        if text in ("复查不通过", "不通过", "违规", "未通过", "维持违规"):
            return CONCLUSION_FAIL
        return None

    @staticmethod
    def _is_effective(review: dict[str, Any]) -> bool:
        # 显式 signed 标记优先；历史已签发记录没有该字段时按状态判断。
        if "signed" in review:
            return bool(review.get("signed")) and review.get("status") in EFFECTIVE_REVIEW_STATUS
        return review.get("status") in EFFECTIVE_REVIEW_STATUS

    @staticmethod
    def _finding_key_of(review: dict[str, Any]) -> str:
        if review.get("finding_key"):
            return str(review["finding_key"])
        return build_finding_key(
            str(review.get("合规条款", "")),
            str(review.get("目标字段", "") or "全表"),
        )

    def _find_effective_review(self, asset_code: str, finding_key: str) -> dict[str, Any] | None:
        for review in store.rows(self.MODULE):
            if review.get("目标资产") != asset_code:
                continue
            if not self._is_effective(review):
                continue
            if self._finding_key_of(review) == finding_key:
                return review
        return None
