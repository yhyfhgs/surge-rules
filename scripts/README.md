# scripts/

Surge JS 脚本目录,存放 `.js` 文件。

脚本承担模块中需要**逻辑判断**的部分:改写响应体、定时签到、事件响应、数据统计。它们由 `modules/` 下的 `.sgmodule` 通过 `[Script]` 段声明并引用 —— 脚本本身不会被 Surge 直接加载。

当前目录只有模板文件,尚无生产脚本。

---

## 命名约定

- **小写 + 连字符**,后缀 `.js`,例如 `ad-block-weibo.js`、`daily-checkin.js`。
- **与引用它的模块同名**,便于对应:`modules/ad-block-weibo.sgmodule` ↔ `scripts/ad-block-weibo.js`。
- `_` 开头的文件是模板(如 `_template.js`)。

---

## 入库标准

新脚本提交前逐条自查:

1. **文件头注释完整** —— 写清用途、脚本类型(`http-response` / `cron` / `event` …)、需要的 `$argument` 参数、匹配的 URL 模式、以及依赖哪个模块。
2. **`$done` 收口** —— **每条执行路径有且只有一次 `$done`**。`$httpClient` 回调的 `error` 分支、`try/catch` 的 `catch` 分支,都要有自己的 `$done`。漏掉的后果是连接挂到超时,表现为"某个 App 偶尔卡几十秒"。
3. **错误处理完整** —— 网络失败、JSON 解析失败、字段缺失都要有兜底。**失败时放行原始内容**,而不是返回空或抛出 —— 脚本坏了不该把功能弄坏。
4. **不阻塞** —— 不做重计算、不做同步长循环。脚本跑在请求链路上,慢一点就是全局卡顿。
5. **配合模块设超时** —— 脚本自身逻辑要能在模块声明的 `timeout` 内跑完;需要更长时间的任务用 `cron` 而不是 `http-*`。
6. **参数化而非硬编码** —— 账号、token、开关一律走 `$argument`(由模块的 `#!arguments` 声明)。**这是公开仓库,任何凭据都不得写进脚本。**
7. **日志克制** —— `console.log` 只在关键分支输出,不要每个请求都打日志刷屏。调试用的详细日志在提交前清掉或收进 debug 开关。
8. **本地验证过** —— 用本地 `script-path` 实测触发过,日志确认行为符合预期,再改远程 URL 提交。

---

## 开发指南

脚本类型、核心 API(`$httpClient` / `$persistentStore` / `$notification` / `$argument` / `$done` / `$environment`)、调试流程与参考项目导读,见 [../docs/DEVELOPMENT.md](../docs/DEVELOPMENT.md)。

新脚本从 [`_template.js`](_template.js) 复制起手,保留其错误处理与 `$done` 结构。
