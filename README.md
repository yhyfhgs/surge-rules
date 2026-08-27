# surge-rules

个人维护的 Surge 分流规则集（本地化自 skk.moe / Repcz / Loyalsoldier / blackmatrix7 等来源，经全局唯一化去重与冲突消解）。

- Surge 引用：`https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/<名称>.list`
- Clash (Verge Rev / Mihomo) 引用：`https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/clash/<名称>.list`（`behavior: classical`、`format: text`）

## Clash 版本（clash/ 目录）

`clash/` 下是由 Surge 源自动派生的 Clash(Mihomo) classical 规则集，文件名一一对应，随每次发布同步再生（`surge2clash.py`，勿手工编辑）。差异处理：`DOMAIN-WILDCARD` 等价转写为 `DOMAIN-REGEX`；`USER-AGENT`/`URL-REGEX` 为 Surge 专有能力，已剔除并在各文件头标注数量。[clash/rule-providers.yaml](clash/rule-providers.yaml) 提供全部 rule-providers 定义与按优先级排列的 rules 参考序列，可在 Clash Verge Rev 的「Merge」扩展中直接取用。

| 列表 | 用途 | 建议策略 |
|---|---|---|
| Reject | 广告/追踪/劫持拦截精简版 | REJECT |
| PrivateLAN / PKU | 内网域名、校园网 | DIRECT |
| GameDownloadCN | 国服游戏下载 CDN（须先于 Games/DownloadCDN） | DIRECT |
| YouTube | YouTube/Music 全量（须先于 Google） | 流媒体 |
| Google / Twitter / Meta | 三大生态（含 Gemini/Grok/Meta AI，须先于 AI） | 家宽组 |
| AI | 独立 AI 服务商 + Apple Intelligence + Copilot | 家宽组 |
| TikTok / SocialOthers | 社交媒体 | 代理 |
| Telegram / Streaming / Games / DownloadCDN | 分类代理 | 代理 |
| Japan / UK / Europe / US | 地区规则 | 地区组 |
| AppleCN / MicrosoftCN | Apple/微软直连（先于 GFW） | DIRECT |
| ProxyGFW | GFW 被墙域名兜底 | 代理 |
| Domestic / ChinaIP | 国内域名与 IP（全 no-resolve） | DIRECT |

规则顺序即优先级，各列表内容互不重叠（每个域名/IP 全链唯一归属）。
