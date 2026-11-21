"""合规复查一致性与评分依据持久化测试。

覆盖场景（题面）：
- 同一张表两项违规（缺少留存依据 / 缺少脱敏凭据），分别按条款复查；
- 一项复查通过后，夜间抵达的旧版扫描批次仍把两项判失败，
  评分必须引用复查结论而非旧批次，负责人只为剩余字段派发工作；
- 并发复查同一条款只认同一次有效签署，两个字段风险分别入账；
- 评分员可说明每项扣分引用的条款、日期、复查号，并单独定位待治理字段；
- 兼容历史已签发的复查记录与无结构化发现项的旧扫描批次。
"""
import threading

import app.store as store_mod
from app.services.compliance_scan import ComplianceScanService
from app.services.compliance_review import ComplianceReviewService
from app.services.govern_score import GovernScoreService

CLAUSE_EVIDENCE = "留存依据管理条款"   # 缺少留存依据
CLAUSE_ANONYM = "敏感数据脱敏条款"     # 缺少脱敏凭据
ASSET = "T-COMP-01"


def _fresh_services():
    store_mod.store.reset()
    return (
        ComplianceScanService(),
        ComplianceReviewService(),
        GovernScoreService(),
    )


def _two_violation_batch(scan_svc, batch_no, scan_time, source="实时扫描"):
    """同一张表同一批次承载两项条款违规（各带字段维度）。"""
    return scan_svc.ingest_scan_batch(
        ASSET,
        [
            {"合规条款": CLAUSE_EVIDENCE, "目标字段": "全表", "是否通过": False,
             "违规描述": "缺少留存依据", "修复意见": "补齐留存依据材料"},
            {"合规条款": CLAUSE_ANONYM, "目标字段": "id_card_no", "是否通过": False,
             "违规描述": "缺少脱敏凭据", "修复意见": "配置脱敏算法与凭据"},
        ],
        batch_no=batch_no,
        source=source,
        scan_time=scan_time,
    )


def _open_issues():
    return [
        it for it in store_mod.store.rows("issue_track")
        if it.get("关联资产") == ASSET and it.get("问题类型") == "合规违规"
        and it.get("status") in ("待确认", "处理中", "待处理")
    ]


# ══════════════════════════════════════════════════════════════════
# 场景 1：两项违规分别复查，通过一项后补入较老的失败批次
# ══════════════════════════════════════════════════════════════════

class TestClauseReviewAndLateBatch:

    def test_two_violations_create_two_field_level_issues(self):
        scan_svc, _, _ = _fresh_services()
        _two_violation_batch(scan_svc, "BATCH-NEW", "2026-11-10 09:00:00")

        open_issues = _open_issues()
        assert len(open_issues) == 2
        keys = {it["finding_key"] for it in open_issues}
        assert f"{CLAUSE_EVIDENCE}|全表" in keys
        assert f"{CLAUSE_ANONYM}|id_card_no" in keys

    def test_review_pass_then_older_failed_batch_keeps_review_conclusion(self):
        scan_svc, review_svc, score_svc = _fresh_services()
        _two_violation_batch(scan_svc, "BATCH-NEW", "2026-11-10 09:00:00")

        # 留存依据已补齐：对该条款签署复查通过
        signed = review_svc.sign_review(
            ASSET, CLAUSE_EVIDENCE, "复查通过", reviewer="合规管理员",
            target_field="全表", evidence="留存依据已归档至证据库 EV-2026-1101",
            ref_batch_no="BATCH-NEW", review_date="2026-11-12 14:30:00",
        )
        assert signed["ok"] is True
        review_no = signed["review"]["复查编号"]

        # 夜间才抵达的旧版扫描（扫描时间更早），仍把两项都判未通过
        late = _two_violation_batch(
            scan_svc, "BATCH-OLD", "2026-11-08 02:00:00", source="历史补报"
        )
        assert late["passed"] is False
        assert late["scan"]["late_arrival"] is True

        conclusions = {c["finding_key"]: c for c in scan_svc.get_clause_conclusions(ASSET)}

        # 已复查条款：采用复查结论，旧批次不能推翻
        evidence_conclusion = conclusions[f"{CLAUSE_EVIDENCE}|全表"]
        assert evidence_conclusion["是否通过"] is True
        assert evidence_conclusion["结论来源"] == "合规复查"
        assert evidence_conclusion["复查编号"] == review_no
        assert evidence_conclusion["复查日期"] == "2026-11-12 14:30:00"

        # 脱敏条款无复查：回退到最新批次结论（按扫描时间，较老批次不覆盖）
        anonym_conclusion = conclusions[f"{CLAUSE_ANONYM}|id_card_no"]
        assert anonym_conclusion["是否通过"] is False
        assert anonym_conclusion["结论来源"] == "扫描批次"
        assert anonym_conclusion["批次编号"] == "BATCH-NEW"

    def test_score_cites_review_number_and_only_remaining_field_is_pending(self):
        scan_svc, review_svc, score_svc = _fresh_services()
        _two_violation_batch(scan_svc, "BATCH-NEW", "2026-11-10 09:00:00")
        signed = review_svc.sign_review(
            ASSET, CLAUSE_EVIDENCE, "复查通过", reviewer="合规管理员",
            target_field="全表", evidence="留存依据已补齐",
            ref_batch_no="BATCH-NEW", review_date="2026-11-12 14:30:00",
        )
        review_no = signed["review"]["复查编号"]
        _two_violation_batch(scan_svc, "BATCH-OLD", "2026-11-08 02:00:00", source="历史补报")

        result = score_svc.evaluate_asset(ASSET)

        # 合规维度仅剩余脱敏一项扣分：100 - 50 = 50
        assert result["dimensions"]["合规条款符合性"] == 50
        evidence = result["compliance_evidence"]
        assert len(evidence) == 2

        by_key = {e["finding_key"]: e for e in evidence}
        passed_item = by_key[f"{CLAUSE_EVIDENCE}|全表"]
        assert passed_item["是否通过"] is True
        assert passed_item["扣分值"] == 0
        assert passed_item["复查编号"] == review_no
        assert passed_item["复查日期"] == "2026-11-12 14:30:00"
        assert "复查号" in passed_item["依据说明"]

        failed_item = by_key[f"{CLAUSE_ANONYM}|id_card_no"]
        assert failed_item["是否通过"] is False
        assert failed_item["扣分值"] == 50
        assert failed_item["批次编号"] == "BATCH-NEW"

        # 可单独找到尚需治理的脱敏字段
        open_violations = result["open_violations"]
        assert len(open_violations) == 1
        assert open_violations[0]["目标字段"] == "id_card_no"
        assert open_violations[0]["合规条款"] == CLAUSE_ANONYM

        # 整改范围只含脱敏字段；留存依据对应待办已关闭
        scope = result["remediation"]
        open_fields = {f["目标字段"] for f in scope["open_fields"]}
        assert open_fields == {"id_card_no"}

        open_issues = _open_issues()
        assert len(open_issues) == 1
        assert open_issues[0]["finding_key"] == f"{CLAUSE_ANONYM}|id_card_no"

        all_issues = [it for it in store_mod.store.rows("issue_track")
                      if it.get("关联资产") == ASSET]
        closed = [it for it in all_issues if it.get("status") == "已验证"]
        assert len(closed) == 1
        assert closed[0]["finding_key"] == f"{CLAUSE_EVIDENCE}|全表"
        assert review_no in closed[0]["closed_reason"]

    def test_sign_pass_closes_remediation_issue_immediately(self):
        scan_svc, review_svc, _ = _fresh_services()
        _two_violation_batch(scan_svc, "BATCH-NEW", "2026-11-10 09:00:00")
        assert len(_open_issues()) == 2

        signed = review_svc.sign_review(
            ASSET, CLAUSE_EVIDENCE, "复查通过", reviewer="合规管理员",
            review_date="2026-11-12 14:30:00",
        )
        # 签署即刻协调整改待办，不必等待下一次评分
        assert len(signed["closed_issue_ids"]) == 1
        assert len(_open_issues()) == 1
        assert _open_issues()[0]["finding_key"] == f"{CLAUSE_ANONYM}|id_card_no"

    def test_revoke_review_reopens_issue_when_batch_still_fails(self):
        scan_svc, review_svc, _ = _fresh_services()
        _two_violation_batch(scan_svc, "BATCH-NEW", "2026-11-10 09:00:00")
        signed = review_svc.sign_review(
            ASSET, CLAUSE_EVIDENCE, "复查通过", reviewer="合规管理员",
            review_date="2026-11-12 14:30:00",
        )
        assert len(_open_issues()) == 1

        review_svc.revoke_review(signed["review"]["id"])
        # 撤销后回退到扫描批次结论（仍违规），待办重新打开
        open_issues = _open_issues()
        assert len(open_issues) == 2
        assert f"{CLAUSE_EVIDENCE}|全表" in {i["finding_key"] for i in open_issues}

    def test_re_score_uses_persisted_evidence_not_current_state_only(self):
        scan_svc, review_svc, score_svc = _fresh_services()
        _two_violation_batch(scan_svc, "BATCH-NEW", "2026-11-10 09:00:00")
        review_svc.sign_review(
            ASSET, CLAUSE_EVIDENCE, "复查通过", reviewer="合规管理员",
            review_date="2026-11-12 14:30:00",
        )
        result = score_svc.evaluate_asset(ASSET)
        score_id = result["score_id"]

        # 重新进入资产评分：直接回查当时持久化的条款依据
        detail = score_svc.get_score_evidence(score_id)
        assert detail["ok"] is True
        assert detail["rebuilt"] is False
        assert len(detail["evidence"]) == 2
        assert any(
            e["合规条款"] == CLAUSE_EVIDENCE and e["复查编号"].startswith("REVI-")
            and e["复查日期"] == "2026-11-12 14:30:00"
            for e in detail["evidence"]
        )
        # 每条依据都能说明条款、日期与复查号/批次号
        for item in detail["evidence"]:
            assert item["合规条款"]
            if item["结论来源"] == "合规复查":
                assert item["复查编号"] and item["复查日期"]
            else:
                assert item["批次编号"] and item["扫描时间"]


# ══════════════════════════════════════════════════════════════════
# 场景 2：并发复查同一条款只认同一次有效签署
# ══════════════════════════════════════════════════════════════════

class TestConcurrentReviewSingleSign:

    def test_concurrent_sign_same_clause_only_one_effective(self):
        _, review_svc, _ = _fresh_services()
        outcomes: list[dict] = []

        def sign(seq: int) -> None:
            outcomes.append(review_svc.sign_review(
                ASSET, CLAUSE_EVIDENCE, "复查通过",
                reviewer=f"复核员{seq}", target_field="全表",
                review_date=f"2026-11-12 1{seq}:00:00",
            ))

        threads = [threading.Thread(target=sign, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        accepted = [o for o in outcomes if o["ok"]]
        rejected = [o for o in outcomes if not o["ok"]]
        assert len(accepted) == 1
        assert len(rejected) == 4
        assert all(o["duplicate"] is True for o in rejected)

        effective = review_svc.get_effective_reviews(ASSET)
        same_clause = [r for r in effective if r["finding_key"] == f"{CLAUSE_EVIDENCE}|全表"]
        assert len(same_clause) == 1

    def test_two_fields_same_clause_family_are_booked_separately(self):
        scan_svc, review_svc, _ = _fresh_services()
        scan_svc.ingest_scan_batch(
            ASSET,
            [
                {"合规条款": CLAUSE_ANONYM, "目标字段": "id_card_no", "是否通过": False,
                 "违规描述": "身份证号缺少脱敏凭据"},
                {"合规条款": CLAUSE_ANONYM, "目标字段": "mobile", "是否通过": False,
                 "违规描述": "手机号缺少脱敏凭据"},
            ],
            batch_no="BATCH-FIELDS", scan_time="2026-11-10 09:00:00",
        )

        r1 = review_svc.sign_review(
            ASSET, CLAUSE_ANONYM, "复查通过", reviewer="甲",
            target_field="id_card_no", review_date="2026-11-12 10:00:00",
        )
        r2 = review_svc.sign_review(
            ASSET, CLAUSE_ANONYM, "复查不通过", reviewer="乙",
            target_field="mobile", review_date="2026-11-12 11:00:00",
        )
        assert r1["ok"] is True and r2["ok"] is True

        conclusions = {c["目标字段"]: c for c in scan_svc.get_clause_conclusions(ASSET)}
        assert conclusions["id_card_no"]["是否通过"] is True
        assert conclusions["mobile"]["是否通过"] is False

        # 同一字段重复签署被拒（只认同一条款一次有效签署）
        dup = review_svc.sign_review(
            ASSET, CLAUSE_ANONYM, "复查通过", reviewer="丙",
            target_field="mobile", review_date="2026-11-12 12:00:00",
        )
        assert dup["ok"] is False and dup["duplicate"] is True

    def test_revoke_allows_resign_but_keeps_audit_trail(self):
        _, review_svc, _ = _fresh_services()
        first = review_svc.sign_review(
            ASSET, CLAUSE_EVIDENCE, "复查不通过", reviewer="甲",
            review_date="2026-11-12 10:00:00",
        )
        review_svc.revoke_review(first["review"]["id"])
        second = review_svc.sign_review(
            ASSET, CLAUSE_EVIDENCE, "复查通过", reviewer="乙",
            review_date="2026-11-13 10:00:00",
        )
        assert second["ok"] is True
        # 历史记录仍在，有效签署只有新的一条
        all_rows = review_svc.get_reviews_by_asset(ASSET)
        assert len(all_rows) == 2
        assert len(review_svc.get_effective_reviews(ASSET)) == 1


# ══════════════════════════════════════════════════════════════════
# 场景 3：兼容历史已签发复查记录与旧版扫描批次
# ══════════════════════════════════════════════════════════════════

class TestLegacyCompatibility:

    def test_legacy_scan_without_structured_findings_is_aggregated(self):
        scan_svc, _, score_svc = _fresh_services()
        # 直接构造历史扫描行：无 clause_findings，违规发现为文本
        store_mod.store.rows("compliance_scan").append({
            "id": 501,
            "任务编号": "COMP-LEGACY-01",
            "目标资产": ASSET,
            "合规条款": "历史合规条款",
            "检查规则": "旧版规则",
            "扫描范围": "全量",
            "违规发现": "历史遗留违规项",
            "修复意见": "专项治理",
            "扫描时间": "2026-09-01 08:00:00",
            "status": "存在违规",
            "pending": True,
            "abnormal": True,
            "created_at": "2026-09-01 08:00:00",
        })
        conclusions = scan_svc.get_clause_conclusions(ASSET)
        assert len(conclusions) == 1
        assert conclusions[0]["合规条款"] == "历史合规条款"
        assert conclusions[0]["是否通过"] is False
        assert conclusions[0]["结论来源"] == "扫描批次"

        result = score_svc.evaluate_asset(ASSET)
        assert result["dimensions"]["合规条款符合性"] == 50
        assert result["compliance_evidence"][0]["违规描述"] == "历史遗留违规项"

    def test_legacy_review_record_without_signed_flag_is_recognized(self):
        scan_svc, review_svc, _ = _fresh_services()
        _two_violation_batch(scan_svc, "BATCH-NEW", "2026-11-10 09:00:00")
        # 模拟历史已签发复查：没有 signed / finding_key 等新字段
        store_mod.store.rows("compliance_review").append({
            "id": 701,
            "复查编号": "REVI-OLD-01",
            "目标资产": ASSET,
            "合规条款": CLAUSE_EVIDENCE,
            "目标字段": "全表",
            "复查结论": "复查通过",
            "复查人": "老复核员",
            "复查日期": "2026-10-01 10:00:00",
            "留存依据": "纸质归档单",
            "引用批次": "BATCH-NEW",
            "复查状态": "复查通过",
            "status": "复查通过",
        })
        conclusions = {c["finding_key"]: c for c in scan_svc.get_clause_conclusions(ASSET)}
        legacy = conclusions[f"{CLAUSE_EVIDENCE}|全表"]
        assert legacy["是否通过"] is True
        assert legacy["复查编号"] == "REVI-OLD-01"
        assert len(scan_svc.get_open_clause_violations(ASSET)) == 1

    def test_legacy_score_without_evidence_rebuilds_basis(self):
        scan_svc, _, score_svc = _fresh_services()
        _two_violation_batch(scan_svc, "BATCH-NEW", "2026-11-10 09:00:00")
        # 历史评分记录：无 compliance_evidence
        store_mod.store.rows("govern_score").append({
            "id": 801,
            "任务编号": "GOVE-OLD-01",
            "评估对象": ASSET,
            "评分维度": "综合评估",
            "当前分数": "72.5",
            "status": "已出分",
            "pending": False,
            "abnormal": False,
            "created_at": "2026-10-01 09:00:00",
        })
        detail = score_svc.get_score_evidence(801)
        assert detail["ok"] is True
        assert detail["rebuilt"] is True
        assert len(detail["evidence"]) == 2
        assert all(e["结论来源"] == "扫描批次" for e in detail["evidence"])

    def test_clause_key_aggregation_ignores_parenthesis_suffix(self):
        scan_svc, review_svc, _ = _fresh_services()
        # 同一扫描项带括号说明，复查使用不带括号的条款名，应聚合为同一键
        scan_svc.ingest_scan_batch(
            ASSET,
            [{"合规条款": f"{CLAUSE_EVIDENCE}（依据 GB/T 35273）",
              "目标字段": "全表", "是否通过": False, "违规描述": "缺少留存依据"}],
            batch_no="BATCH-SUFFIX", scan_time="2026-11-10 09:00:00",
        )
        signed = review_svc.sign_review(
            ASSET, CLAUSE_EVIDENCE, "复查通过", reviewer="合规管理员",
            review_date="2026-11-12 14:30:00",
        )
        assert signed["ok"] is True
        conclusions = scan_svc.get_clause_conclusions(ASSET)
        assert len(conclusions) == 1
        assert conclusions[0]["是否通过"] is True
        assert conclusions[0]["结论来源"] == "合规复查"


# ══════════════════════════════════════════════════════════════════
# 场景 4：实时扫描链路仍产出结构化条款发现项
# ══════════════════════════════════════════════════════════════════

class TestRealtimeScanStructuredFindings:

    def test_scan_asset_persists_clause_findings_and_batch_metadata(self):
        scan_svc, _, _ = _fresh_services()
        result = scan_svc.scan_asset(
            ASSET, "数据安全合规",
            ["分类标签复核", "脱敏规则完备性", "契约合规", "审计异常"],
        )
        assert "clause_findings" in result["scan"]
        assert result["scan"]["批次编号"].startswith("BATCH-")
        assert result["scan"]["批次来源"] == "实时扫描"
        # 无违规时也保留一条通过型条款发现，聚合不缺条款
        assert result["passed"] is True
        assert result["clause_findings"][0]["是否通过"] is True
