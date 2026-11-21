"""治理评分领域服务：多维度治理健康评分、改进跟踪和整改闭环。

接收血缘追踪、标签传播、变更捕获等各上游模块的数据作为评分维度。

合规扣分改造：
- 新增「合规条款符合性」维度，取数完全沿合规扫描服务的条款聚合口径：
  有效复查签署优先，无复查取最新扫描批次；夜间旧批次不能推翻已通过复查。
- 每个未通过条款字段独立扣分并把依据（条款、日期、复查号/批次号、字段）
  持久化到评分记录的 compliance_evidence，重新进入评分可逐条核对当时条款。
- 评分同时协调整改待办：复查通过的条款关闭待办，剩余未通过字段各自保留
  一条待办，负责人按当前扣分派发剩余工作。
"""
from __future__ import annotations

import time as _time
from typing import Any

from app.services.base import BaseModuleService
from app.services.compliance_scan import ComplianceScanService
from app.store import store

# 每个未通过条款字段的固定扣分值，扣分下限为 0
DEDUCTION_PER_FAILED_CLAUSE = 50


class GovernScoreService(BaseModuleService):
    MODULE = "govern_score"
    ENTITY = "评分任务"
    OPERATION_TERM = "校验"
    LIST_FIELDS = ["任务编号", "评估对象", "评分维度", "当前分数", "改进基线", "评估周期", "预警级别", "整改状态"]
    REQUIRED_FIELDS = ["任务编号", "评估对象", "评分维度"]
    STATUS_ORDER = ["待评估", "评估中", "已出分", "整改中"]
    ACTION_RULES = {"发起评估": "评估中", "确认评分": "已出分", "指派整改": "整改中"}
    NEGATIVE_ACTIONS = ["指派整改"]

    SCORE_DIMENSIONS = {
        "元数据完备性": {"base": 100, "field": "metadata", "weight": 0.15},
        "质量监控覆盖": {"base": 80, "field": "quality", "weight": 0.20},
        "分级标签准确度": {"base": 70, "field": "classification", "weight": 0.15},
        "血缘完备性": {"base": 60, "field": "lineage", "weight": 0.20},
        "标签覆盖": {"base": 50, "field": "tag", "weight": 0.10},
        "契约合规": {"base": 40, "field": "contract", "weight": 0.10},
        "负责人到位": {"base": 30, "field": "owner", "weight": 0.10},
        # 新增合规维度，权重 0.10；加权时按实际权重和归一，不改动既有维度
        "合规条款符合性": {"base": 100, "field": "compliance", "weight": 0.10},
    }

    def evaluate_asset(self, asset_code: str) -> dict[str, Any]:
        """对资产进行多维度治理评分（Pipeline 7 汇总输出）。"""
        dimensions = {}

        # 元数据完备性
        metadata = store.find_by_field("metadata_index", "所属资产", asset_code)
        dimensions["元数据完备性"] = min(100, len(metadata) * 20)

        # 质量监控覆盖
        quality = store.find_by_field("quality_rule", "目标资产", asset_code)
        dimensions["质量监控覆盖"] = min(100, len(quality) * 33)

        # 分级标签准确度
        classifications = [
            c for c in store.rows("classification")
            if str(c.get("目标字段", "")).startswith(f"{asset_code}.")
        ]
        dimensions["分级标签准确度"] = min(
            100, len([c for c in classifications if c.get("status") == "已确认"]) * 25
        )

        # 血缘完备性
        lineage = [
            l for l in store.rows("lineage_track")
            if l.get("上游资产") == asset_code or l.get("下游资产") == asset_code
        ]
        dimensions["血缘完备性"] = min(100, len(lineage) * 25)

        # 标签覆盖
        tag_assets = [t.get("关联资产数", "0") for t in store.rows("tag_registry")]
        dimensions["标签覆盖"] = min(100, 50 + len(tag_assets) * 5)

        # 契约合规
        contracts = store.find_by_field("data_contract", "数据资产", asset_code)
        dimensions["契约合规"] = min(
            100, len([c for c in contracts if c.get("status") == "已签署"]) * 50
        )

        # 负责人到位
        owners = store.find_by_field("owner_mgr", "目标资产", asset_code)
        dimensions["负责人到位"] = min(
            100, len([o for o in owners if o.get("status") == "已生效"]) * 50
        )

        # 合规条款符合性：沿合规扫描聚合口径取数，扣分依据全部留存
        compliance_dim, clause_conclusions, compliance_evidence = self._evaluate_compliance(asset_code)
        dimensions["合规条款符合性"] = compliance_dim

        # 加权总分（按实际权重和归一，新增维度不影响既有口径的自洽性）
        total = 0.0
        weight_sum = 0.0
        for dim, cfg in self.SCORE_DIMENSIONS.items():
            score = dimensions.get(dim, cfg["base"])
            total += score * cfg["weight"]
            weight_sum += cfg["weight"]
        overall = round(total / max(weight_sum, 0.01), 1)

        open_violations = [c for c in clause_conclusions if not c["是否通过"]]
        scored_at = _time.strftime("%Y-%m-%d %H:%M:%S")

        # 保存评分记录（含持久化的合规扣分依据）
        score_id = store.next_id(self.MODULE)
        score_entry = {
            "id": score_id,
            "任务编号": f"GOVE-{score_id:04d}",
            "评估对象": asset_code,
            "评分维度": "综合评估",
            "当前分数": str(overall),
            "改进基线": self._compute_baseline(dimensions, overall),
            "评估周期": "按需",
            "预警级别": self._severity_label(overall),
            "整改状态": "整改中" if open_violations else "已出分",
            "status": "整改中" if open_violations else "已出分",
            "pending": overall < 60 or bool(open_violations),
            "abnormal": overall < 40,
            "dimensions": dimensions,
            # 合规复查评分依据：重新进入资产评分时可核对当时引用的条款
            "compliance_evidence": compliance_evidence,
            "clause_conclusions": clause_conclusions,
            "open_violation_count": len(open_violations),
            "scored_at": scored_at,
            "created_at": scored_at,
        }
        store.rows(self.MODULE).append(score_entry)

        # 整改待办随评分更新：通过项关闭、剩余未通过字段分别保留待办
        remediation = ComplianceScanService().reconcile_remediation_issues(asset_code)
        score_entry["remediation_scope"] = {
            "open_issue_ids": [i.get("id") for i in remediation["opened"]],
            "closed_issue_ids": [i.get("id") for i in remediation["closed"]],
            "open_fields": [
                {"合规条款": c.get("合规条款"), "目标字段": c.get("目标字段"),
                 "finding_key": c.get("finding_key")}
                for c in open_violations
            ],
        }

        self.emit_event("governance_scored", {
            "score_id": score_id,
            "asset_code": asset_code,
            "overall": overall,
            "dimensions": dimensions,
            "open_violation_count": len(open_violations),
        })

        return {
            "score_id": score_id,
            "asset": asset_code,
            "overall": overall,
            "dimensions": dimensions,
            "compliance_evidence": compliance_evidence,
            "open_violations": open_violations,
            "remediation": score_entry["remediation_scope"],
            "pipeline": "compliance_scan->compliance_review->govern_score->issue_track",
        }

    def get_score_evidence(self, score_id: int) -> dict[str, Any]:
        """回查某次评分引用的全部条款依据。

        兼容历史已签发评分：旧记录没有 compliance_evidence 时基于当前条款
        结论即时重建，并显式标注为补建依据，不伪造历史复查号。
        """
        entry = store.find(self.MODULE, score_id)
        if entry is None:
            return {"ok": False, "message": f"评分任务 {score_id} 不存在"}

        evidence = entry.get("compliance_evidence")
        rebuilt = False
        if not evidence:
            asset_code = str(entry.get("评估对象", ""))
            conclusions = ComplianceScanService().get_clause_conclusions(asset_code)
            evidence = [self._build_evidence_item(c) for c in conclusions]
            rebuilt = True

        return {
            "ok": True,
            "score_id": score_id,
            "任务编号": entry.get("任务编号", ""),
            "评估对象": entry.get("评估对象", ""),
            "scored_at": entry.get("scored_at", entry.get("created_at", "")),
            "overall": entry.get("当前分数", ""),
            "rebuilt": rebuilt,
            "evidence": evidence,
        }

    # ── 合规取数与扣分依据 ────────────────────────────────────

    def _evaluate_compliance(
        self, asset_code: str
    ) -> tuple[int, list[dict[str, Any]], list[dict[str, Any]]]:
        """沿扫描服务的条款聚合结论计算合规维度并留存每条依据。"""
        conclusions = ComplianceScanService().get_clause_conclusions(asset_code)
        evidence = [self._build_evidence_item(c) for c in conclusions]
        failed = [c for c in conclusions if not c["是否通过"]]
        score = max(0, 100 - DEDUCTION_PER_FAILED_CLAUSE * len(failed))
        return score, conclusions, evidence

    @staticmethod
    def _build_evidence_item(conclusion: dict[str, Any]) -> dict[str, Any]:
        """单条扣分/通过依据：评分员可据此说明条款、日期和复查号。"""
        from_review = conclusion.get("结论来源") == "合规复查"
        return {
            "finding_key": conclusion.get("finding_key", ""),
            "合规条款": conclusion.get("合规条款", ""),
            "目标字段": conclusion.get("目标字段", "全表"),
            "有效结论": conclusion.get("有效结论", ""),
            "结论来源": conclusion.get("结论来源", ""),
            "是否通过": conclusion.get("是否通过", False),
            "扣分值": 0 if conclusion.get("是否通过") else DEDUCTION_PER_FAILED_CLAUSE,
            # 复查路径：复查号 + 复查日期 + 留存依据
            "复查编号": conclusion.get("复查编号", ""),
            "复查日期": conclusion.get("复查日期", ""),
            "复查人": conclusion.get("复查人", ""),
            "留存依据": conclusion.get("留存依据", ""),
            # 扫描路径：批次号 + 扫描时间
            "批次编号": conclusion.get("批次编号", ""),
            "扫描时间": conclusion.get("扫描时间", ""),
            "违规描述": conclusion.get("违规描述", ""),
            "依据说明": (
                f"条款「{conclusion.get('合规条款', '')}」字段「{conclusion.get('目标字段', '全表')}」"
                f"{conclusion.get('有效结论', '')}"
                + (f"，复查号{conclusion.get('复查编号', '')}，复查日期{conclusion.get('复查日期', '')}"
                   if from_review and conclusion.get("复查编号")
                   else f"，批次{conclusion.get('批次编号', '')}，扫描时间{conclusion.get('扫描时间', '')}")
            ),
        }

    def _compute_baseline(self, dims: dict[str, int], overall: float) -> str:
        """计算改进基线。"""
        weaknesses = [(d, s) for d, s in dims.items() if s < 60]
        if weaknesses:
            weakest = min(weaknesses, key=lambda x: x[1])
            return f"加强{weakest[0]}（当前{weakest[1]}分）"
        if overall < 80:
            return "各维度持续改进以达到优良水平"
        return "维持当前水平"

    def _severity_label(self, score: float) -> str:
        if score >= 80:
            return "正常"
        elif score >= 60:
            return "需关注"
        elif score >= 40:
            return "严重"
        return "危急"

    def get_scores_by_asset(self, asset_code: str) -> list[dict[str, Any]]:
        """获取资产的所有治理评分记录。"""
        return store.find_by_field(self.MODULE, "评估对象", asset_code)
