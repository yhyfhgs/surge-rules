# modules/

Surge 模块目录,存放 `.sgmodule` 文件。

模块负责把 `[Rule]`、`[URL Rewrite]`、`[Header Rewrite]`、`[Map Local]`、`[Script]`、`[MITM]` 等能力打包成一个可独立安装 / 卸载的单元 —— 与 `lists/` 下的纯分流规则集职责分明:**规则集决定流量走哪条线路,模块决定流量本身被怎么处理。**

当前目录只有模板文件,尚无生产模块。

---

## 命名约定

- **小写 + 连字符**,后缀 `.sgmodule`,例如 `ad-block-weibo.sgmodule`、`daily-checkin.sgmodule`。
- 名字要说明**做什么**,不是**给谁做**:`ad-block-weibo` 优于 `weibo`。
- `_` 开头的文件是模板,不是可安装模块(如 `_template.sgmodule`)。

---

## 入库标准

新模块提交前逐条自查:

1. **元信息完整** —— `#!name` / `#!desc` / `#!category` / `#!system` 都要填。`#!desc` 用一句话说清用途和副作用。
2. **注释完整** —— 每个功能段前写明这段在做什么;每条 rewrite / script 声明旁注明针对哪个 App 或页面。半年后回来看,注释是唯一线索。
3. **`hostname` 必须走 `%APPEND%`** —— 写成 `hostname = %APPEND% a.example.com, b.example.com`。**漏掉 `%APPEND%` 会覆盖全局 hostname 列表,静默毁掉其他所有模块的 MitM 能力。**
4. **hostname 收敛** —— 只声明真正需要解密的域名,具体域名优先于通配。每多一个域名都是性能与兼容性成本。
5. **脚本声明必设 `timeout` 与 `max-size`** —— 没有超时的脚本会把连接挂死;没有 body 上限的脚本会被大响应拖垮。
6. **script-path 用远程 URL** —— 入库版本指向 `@main/scripts/<name>.js`,本地路径只用于调试阶段。
7. **不含任何敏感内容** —— 这是**公开仓库**。节点信息、CA 证书及其口令、账号 token、Cookie 一律不得出现。需要用户提供的值走 `#!arguments` 参数化。
8. **本地验证过** —— 在 Surge 中从文件安装、实际触发、日志确认行为符合预期,再提交。

---

## 开发指南

完整的格式规范、脚本 API、MitM 原理、调试流程与参考项目导读,见 [../docs/DEVELOPMENT.md](../docs/DEVELOPMENT.md)。

新模块从 [`_template.sgmodule`](_template.sgmodule) 复制起手。
