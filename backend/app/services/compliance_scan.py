"""合规扫描领域服务：数据资产的合规性自动扫描、违规发现和修复追踪。

接收数据契约的Schema验证和操作日志的异常检测作为扫描输入。

条款化改造：
- 每条扫描批次把违规发现拆成结构化条款发现项（clause_findings），
  同一批次可同时承载多个条款/字段的结论（同一张表两项违规落在同批次）。
- 扫描批次只反映「扫描当时」的系统判断；夜间抵达的旧版补报按其自带
  扫描时间留痕，但不会推翻已经完成的合规复查。
- 资产级条款结论由 get_clause_conclusions 聚合：已有效签署的复查优先，
  无复查时取该条款最新扫描批次的结论，治理评分沿这条取数逻辑扣分。
"""
from __future__ import annotations

import time as _time
from typing import Any

from app.services.base import BaseModuleService
from app.store import store

# 结论状态词（与合规复查服务共用同一套中文词，便于取数对齐）
SCAN_PASS = "已通过"
SCAN_VIOLATION = "存在违规"
REVIEW_PASS = "复查通过"
REVIEW_FAIL = "复查不通过"


def clause_key_of(clause: str) -> str:
    """合规条款归一化键：忽略括号补充说明和首尾空白，聚合时按此归并。"""
    text = str(clause or "").strip()
    for sep in ("(", "（"):
        if sep in text:
            text = text.split(sep, 1)[0].strip()
    return text or "未命名条款"


def build_finding_key(clause: str, target_field: str) -> str:
    """条款发现项维度键：条款 + 目标字段。字段各自的风险分别入账。"""
    field = str(target_field or "").strip() or "全表"
    return f"{clause_key_of(clause)}|{field}"


class ComplianceScanService(BaseModuleService):
    MODULE = "compliance_scan"
    ENTITY = "扫描任务"
    OPERATION_TERM = "校验"
    LIST_FIELDS = ["任务编号", "目标资产", "合规条款", "检查规则", "扫描范围", "违规发现", "修复意见", "扫描时间"]
    REQUIRED_FIELDS = ["任务编号", "目标资产", "合规条款"]
    STATUS_ORDER = ["待扫描", "扫描中", "已通过", "存在违规"]
    ACTION_RULES = {"启动扫描": "扫描中", "确认通过": "已通过", "标记违规": "存在违规"}
    NEGATIVE_ACTIONS = ["标记违规"]

    def scan_asset(self, asset_code: str, compliance_clause: str, check_rules: list[str]) -> dict[str, Any]:
        """对资产执规扫描（Pipeline 5/8 核心方法）。"""
        scan_id = store.next_id(self.MODULE)
        violations, findings = self._run_rule_checks(asset_code, compliance_clause, check_rules)
        passed = len(violations) == 0
        scan_time = _time.strftime("%Y-%m-%d %H:%M:%S")

        scan = {
            "id": scan_id,
            "任务编号": f"COMP-{scan_id:04d}",
            "目标资产": asset_code,
            "合规条款": compliance_clause,
            "检查规则": "; ".join(check_rules),
            "扫描范围": "全量",
            "违规发现": "; ".join(violations) if violations else "",
            "修复意见": self._generate_remediation(violations),
            "扫描时间": scan_time,
            "status": SCAN_PASS if passed else SCAN_VIOLATION,
            "pending": not passed,
            "abnormal": not passed,
            # 条款化批次元数据
            "批次编号": f"BATCH-{scan_id:04d}",
            "批次来源": "实时扫描",
            "batch_time": scan_time,
            "clause_findings": findings,
            "created_at": scan_time,
        }
        store.rows(self.MODULE).append(scan)

        # 违规治理问题统一由条款级协调创建：每个条款字段一条待办，可独立关闭
        if not passed:
            self.reconcile_remediation_issues(asset_code)

        store.log_change(
            self.MODULE, scan_id, "合规扫描",
            before=None, after=f"{'通过' if passed else '违规'}: {len(violations)}项违规",
            source="pipeline_5", scope="compliance_scan"
        )

        self.emit_event("compliance_scanned", {
            "scan_id": scan_id,
            "asset_code": asset_code,
            "passed": passed,
            "violations_count": len(violations),
        })

        return {
            "scan": scan,
            "passed": passed,
            "violations": violations,
            "clause_findings": findings,
            "pipeline": "compliance_scan->issue_track" if not passed else None,
        }

    def ingest_scan_batch(
        self,
        asset_code: str,
        findings: list[dict[str, Any]],
        *,
        batch_no: str | None = None,
        source: str = "历史补报",
        scan_time: str | None = None,
        check_rules: str = "",
    ) -> dict[str, Any]:
        """接收一个扫描批次（含夜间抵达的旧版扫描补报）。

        findings 为条款级结论列表，每项形如：
        {"合规条款": ..., "目标字段": "全表"/具体字段, "是否通过": bool,
         "违规描述": "...", "修复意见": "..."}
        批次按自带 scan_time 留痕；聚合有效结论时复查签署始终优先于批次。
        """
        scan_id = store.next_id(self.MODULE)
        scan_time = scan_time or _time.strftime("%Y-%m-%d %H:%M:%S")
        structured = [self._normalize_finding(asset_code, f) for f in findings]
        violations = [f["违规描述"] for f in structured if not f["是否通过"]]
        passed = not violations

        scan = {
            "id": scan_id,
            "任务编号": f"COMP-BATCH-{scan_id:04d}",
            "目标资产": asset_code,
            "合规条款": "; ".join(sorted({clause_key_of(f["合规条款"]) for f in structured})),
            "检查规则": check_rules or "批量条款核查",
            "扫描范围": "全量",
            "违规发现": "; ".join(violations),
            "修复意见": self._generate_remediation(violations),
            "扫描时间": scan_time,
            "status": SCAN_PASS if passed else SCAN_VIOLATION,
            "pending": not passed,
            "abnormal": not passed,
            "批次编号": batch_no or f"BATCH-{scan_id:04d}",
            "批次来源": source,
            "batch_time": scan_time,
            "clause_findings": structured,
            "late_arrival": source == "历史补报",
            "created_at": _time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        store.rows(self.MODULE).append(scan)

        # 无论批次新旧都重新协调一次：旧批次不能把已复查通过的待办重新打开，
        # 仍未通过的条款字段则各自保证一条未关闭待办
        self.reconcile_remediation_issues(asset_code)

        store.log_change(
            self.MODULE, scan_id, "扫描批次补报",
            before=None,
            after=f"批次{scan['批次编号']} {len(violations)}项违规（扫描时间{scan_time}）",
            source="batch_ingest", scope="compliance_scan",
        )
        return {
            "scan": scan,
            "batch_no": scan["批次编号"],
            "passed": passed,
            "violations": violations,
            "clause_findings": structured,
        }

    # ── 条款聚合：评分采用的唯一取数口径 ───────────────────────

    def get_clause_conclusions(self, asset_code: str) -> list[dict[str, Any]]:
        """聚合资产当前有效的条款结论。

        优先级：同一条款+字段存在有效复查签署 → 采用复查结论（带复查号、
        复查日期、留存依据）；否则回退到该条款最新扫描批次的结论
        （带批次编号、扫描时间）。旧版补报不会覆盖已签署结论。
        """
        from app.services.compliance_review import ComplianceReviewService

        review_map = ComplianceReviewService().effective_review_map(asset_code)
        # finding_key -> 最新批次中的发现项（按扫描时间取最新）
        latest_scan: dict[str, dict[str, Any]] = {}
        for scan in self._asset_scans(asset_code):
            for finding in self._findings_of(scan):
                key = finding["finding_key"]
                incumbent = latest_scan.get(key)
                if incumbent is None or str(scan.get("扫描时间", "")) >= str(incumbent.get("_scan_time", "")):
                    latest_scan[key] = {**finding, "_scan_time": scan.get("扫描时间", ""),
                                        "_batch_no": scan.get("批次编号", ""),
                                        "_scan_id": scan.get("id")}

        all_keys = set(review_map) | set(latest_scan)
        conclusions: list[dict[str, Any]] = []
        for key in sorted(all_keys):
            review = review_map.get(key)
            scan_finding = latest_scan.get(key)
            if review is not None:
                conclusions.append({
                    "finding_key": key,
                    "合规条款": review.get("合规条款", ""),
                    "目标字段": review.get("目标字段", "全表"),
                    "有效结论": review.get("复查结论"),
                    "结论来源": "合规复查",
                    "是否通过": review.get("复查结论") == REVIEW_PASS,
                    "复查编号": review.get("复查编号", ""),
                    "复查日期": review.get("复查日期", ""),
                    "复查人": review.get("复查人", ""),
                    "留存依据": review.get("留存依据", ""),
                    "引用批次": review.get("引用批次", ""),
                    "批次编号": review.get("引用批次", "") or (scan_finding or {}).get("_batch_no", ""),
                    "扫描时间": (scan_finding or {}).get("_scan_time", ""),
                    "违规描述": (scan_finding or {}).get("违规描述", ""),
                })
            else:
                conclusions.append({
                    "finding_key": key,
                    "合规条款": scan_finding["合规条款"],
                    "目标字段": scan_finding["目标字段"],
                    "有效结论": SCAN_VIOLATION if not scan_finding["是否通过"] else SCAN_PASS,
                    "结论来源": "扫描批次",
                    "是否通过": scan_finding["是否通过"],
                    "复查编号": "",
                    "复查日期": "",
                    "复查人": "",
                    "留存依据": "",
                    "引用批次": "",
                    "批次编号": scan_finding.get("_batch_no", ""),
                    "扫描时间": scan_finding.get("_scan_time", ""),
                    "违规描述": scan_finding.get("违规描述", ""),
                })
        return conclusions

    def get_open_clause_violations(self, asset_code: str) -> list[dict[str, Any]]:
        """当前仍需治理的条款字段（负责人据此派发剩余工作）。"""
        return [c for c in self.get_clause_conclusions(asset_code) if not c["是否通过"]]

    # ── 整改待办协调：随评分/复查更新 ─────────────────────────

    def reconcile_remediation_issues(self, asset_code: str) -> dict[str, Any]:
        """按当前条款结论协调治理问题（issue_track）。

        - 已复查通过的条款字段：关闭对应待办（已修复/已验证），不重复开单；
        - 仍未通过的条款字段：确保各有一条未关闭待办，两个字段分别入账；
        - 夜间旧批次判失败但条款已复查通过时，不会重新打开已关闭待办。
        """
        conclusions = self.get_clause_conclusions(asset_code)
        issue_rows = store.rows("issue_track")
        opened: list[dict[str, Any]] = []
        closed: list[dict[str, Any]] = []

        for conclusion in conclusions:
            key = conclusion["finding_key"]
            linked = [
                it for it in issue_rows
                if it.get("关联资产") == asset_code
                and str(it.get("finding_key", "")) == key
                and it.get("问题类型") == "合规违规"
            ]
            if conclusion["是否通过"]:
                for issue in linked:
                    if issue.get("status") in ("待确认", "处理中", "待处理"):
                        issue["status"] = "已验证"
                        issue["当前状态"] = "已验证"
                        issue["pending"] = False
                        issue["abnormal"] = False
                        issue["closed_reason"] = (
                            f"条款复查通过（{conclusion.get('复查编号', '') or conclusion.get('批次编号', '')}）"
                        )
                        issue["closed_at"] = _time.strftime("%Y-%m-%d %H:%M:%S")
                        closed.append(issue)
                continue

            open_issue = next(
                (it for it in linked if it.get("status") in ("待确认", "处理中", "待处理")),
                None,
            )
            if open_issue is None:
                opened.append(self._create_clause_issue(asset_code, conclusion))
            else:
                # 待办已存在则保持单条，补齐最新依据引用
                open_issue["评分依据"] = self._basis_summary(conclusion)

        return {
            "asset": asset_code,
            "opened": opened,
            "closed": closed,
            "open_violations": self.get_open_clause_violations(asset_code),
        }

    # ── 原有查询接口 ─────────────────────────────────────────

    def get_scans_by_asset(self, asset_code: str) -> list[dict[str, Any]]:
        return store.find_by_field(self.MODULE, "目标资产", asset_code)

    def get_violations(self) -> list[dict[str, Any]]:
        return [r for r in store.rows(self.MODULE) if r.get("status") == SCAN_VIOLATION]

    # ── 内部工具 ──────────────────────────────────────────────

    def _run_rule_checks(
        self, asset_code: str, compliance_clause: str, check_rules: list[str]
    ) -> tuple[list[str], list[dict[str, Any]]]:
        """执行规则检查，同时产出文本违规列表与结构化条款发现项。"""
        violations: list[str] = []
        findings: list[dict[str, Any]] = []

        def add_finding(field: str, description: str, advice: str) -> None:
            violations.append(description)
            findings.append(self._normalize_finding(asset_code, {
                "合规条款": compliance_clause,
                "目标字段": field,
                "是否通过": False,
                "违规描述": description,
                "修复意见": advice,
            }))

        for rule in check_rules:
            if "分类" in rule or "classification" in rule.lower():
                classifications = [
                    c for c in store.rows("classification")
                    if str(c.get("目标字段", "")).startswith(f"{asset_code}.")
                ]
                pending = [c for c in classifications if c.get("status") == "待复核"]
                if pending:
                    add_finding(
                        "全表",
                        f"存在{len(pending)}个待复核的分级标签",
                        "完成分级标签人工复核并确认敏感等级",
                    )

            if "脱敏" in rule or "anonym" in rule.lower():
                for c in store.rows("classification"):
                    if str(c.get("目标字段", "")).startswith(f"{asset_code}."):
                        if c.get("敏感等级") == "高" and c.get("status") == "已确认":
                            field_name = str(c.get("目标字段", ""))
                            anonym_rules = store.find_by_field("data_anonym", "目标字段", field_name)
                            if not anonym_rules:
                                short_field = field_name.split(".", 1)[1] if "." in field_name else field_name
                                add_finding(
                                    short_field,
                                    f"高敏感字段{field_name}缺少脱敏规则",
                                    f"为字段{short_field}配置脱敏算法并补全脱敏凭据",
                                )

            if "契约" in rule or "contract" in rule.lower():
                contracts = store.find_by_field("data_contract", "数据资产", asset_code)
                violated = [c for c in contracts if c.get("status") == "已违约"]
                if violated:
                    add_finding(
                        "全表",
                        f"存在{len(violated)}个违约契约",
                        "修复Schema偏离或重新协商数据契约",
                    )

            if "操作" in rule or "log" in rule.lower():
                anomalies = [
                    a for a in store.rows("operation_log")
                    if a.get("目标资产") == asset_code and a.get("status") == "已异常"
                ]
                if anomalies:
                    add_finding(
                        "全表",
                        f"存在{len(anomalies)}条异常操作记录需要核实",
                        "逐条核实异常操作并补充审计说明",
                    )

        if not findings:
            findings.append(self._normalize_finding(asset_code, {
                "合规条款": compliance_clause,
                "目标字段": "全表",
                "是否通过": True,
                "违规描述": "",
                "修复意见": "无需修复",
            }))
        return violations, findings

    def _normalize_finding(self, asset_code: str, raw: dict[str, Any]) -> dict[str, Any]:
        clause = str(raw.get("合规条款", "")).strip()
        field = str(raw.get("目标字段", "") or "全表").strip() or "全表"
        passed = bool(raw.get("是否通过"))
        description = str(raw.get("违规描述", "") or "")
        return {
            "合规条款": clause,
            "clause_key": clause_key_of(clause),
            "目标字段": field,
            "finding_key": build_finding_key(clause, field),
            "目标资产": asset_code,
            "是否通过": passed,
            "违规描述": description,
            "修复意见": str(raw.get("修复意见", "") or ""),
        }

    def _findings_of(self, scan: dict[str, Any]) -> list[dict[str, Any]]:
        """读取批次的结构化发现项；兼容历史已签发、无 clause_findings 的扫描。"""
        existing = scan.get("clause_findings")
        if isinstance(existing, list) and existing:
            return [self._normalize_finding(scan.get("目标资产", ""), f) for f in existing]

        asset_code = str(scan.get("目标资产", ""))
        clause = str(scan.get("合规条款", "")).strip() or "未命名条款"
        if scan.get("status") == SCAN_VIOLATION or str(scan.get("违规发现", "")).strip() not in ("", "-"):
            text = str(scan.get("违规发现", "")).strip()
            return [self._normalize_finding(asset_code, {
                "合规条款": clause,
                "目标字段": "全表",
                "是否通过": False,
                "违规描述": text,
                "修复意见": str(scan.get("修复意见", "")),
            })]
        # 历史通过批次：给出一条通过型发现项，保证聚合时条款不缺失
        return [self._normalize_finding(asset_code, {
            "合规条款": clause,
            "目标字段": "全表",
            "是否通过": True,
            "违规描述": "",
            "修复意见": "",
        })]

    def _asset_scans(self, asset_code: str) -> list[dict[str, Any]]:
        return [s for s in store.rows(self.MODULE) if s.get("目标资产") == asset_code]

    def _generate_remediation(self, violations: list[str]) -> str:
        if not violations:
            return "无需修复"
        return f"发现{len(violations)}项违规: {'; '.join(violations)}。建议逐一确认并制定修复方案。"

    def _create_clause_issue(self, asset_code: str, conclusion: dict[str, Any]) -> dict[str, Any]:
        """为单个未通过条款字段创建/补齐整改待办，字段风险分别入账。"""
        issue_id = store.next_id("issue_track")
        field = conclusion.get("目标字段", "全表")
        issue = {
            "id": issue_id,
            "问题编号": f"ISSU-CLAUSE-{issue_id:04d}",
            "关联资产": asset_code,
            "问题类型": "合规违规",
            "严重级别": "需关注",
            "指派处理": "合规管理员",
            "当前状态": "待处理",
            "修复方案": (
                f"[{conclusion.get('合规条款', '')}/{field}] "
                f"{conclusion.get('违规描述', '') or '条款核查未通过'}；"
                f"{('整改后提交合规复查') if conclusion.get('结论来源') == '扫描批次' else '维持违规，继续治理'}"
            ),
            "截止日期": _time.strftime("%Y-%m-%d", _time.localtime(_time.time() + 86400 * 14)),
            "status": "待确认",
            "pending": True,
            "abnormal": True,
            "finding_key": conclusion["finding_key"],
            "合规条款": conclusion.get("合规条款", ""),
            "目标字段": field,
            "批次编号": conclusion.get("批次编号", ""),
            "复查编号": conclusion.get("复查编号", ""),
            "评分依据": self._basis_summary(conclusion),
            "created_at": _time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        store.rows("issue_track").append(issue)
        return issue

    @staticmethod
    def _basis_summary(conclusion: dict[str, Any]) -> str:
        if conclusion.get("结论来源") == "合规复查":
            return (
                f"{conclusion.get('有效结论')}｜条款:{conclusion.get('合规条款', '')}"
                f"｜复查号:{conclusion.get('复查编号', '')}｜日期:{conclusion.get('复查日期', '')}"
            )
        return (
            f"{conclusion.get('有效结论')}｜条款:{conclusion.get('合规条款', '')}"
            f"｜批次:{conclusion.get('批次编号', '')}｜扫描时间:{conclusion.get('扫描时间', '')}"
        )
