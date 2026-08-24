# surge-rules

个人维护的 Surge 分流规则集（本地化自 skk.moe / Repcz / Loyalsoldier / blackmatrix7 等来源，经全局唯一化去重与冲突消解）。

通过 jsDelivr 引用：`https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/<名称>.list`

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
