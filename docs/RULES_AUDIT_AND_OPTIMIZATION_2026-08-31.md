# Surge 规则全量审计与精准分流迭代方案

> 审计日期：2026-08-31（Asia/Shanghai）<br>
> 原始基线：`a1c3efc9e02b2f930cc07007a76253f932967081`<br>
> 实测运行时：Surge Mac 6.9.0（Core 6009000）、Mihomo 1.19.20。<br>
> 原始对象：仓库跟踪文件、34 个 Surge 源 list、Clash 派生层、真实 `Surge.conf` 规则序及测试/发布链路。

## Archived / superseded

This report is retained as provenance only. Its 2026-08-31 findings and proposed iteration plan are superseded by the verified rule-topology analysis in [`RULE_ANALYSIS_2026-09-01.md`](RULE_ANALYSIS_2026-09-01.md). That document is the current diagnostic reference for extraction, containment/overlap matching, list-order constraints, regional placement, CN/proxy separation, and `ProxyGFW` reclassification.

The complete historical report remains recoverable with `git show e03c530:docs/RULES_AUDIT_AND_OPTIMIZATION_2026-08-31.md`. Related raw evidence is retained under [`reference/audit-v2-20260831/`](../reference/audit-v2-20260831/). Do not combine this report’s pre-refactor counts or policy assumptions with the 2026-09-01 baseline.
