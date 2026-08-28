/**
 * _template.js — Surge 脚本模板
 *
 * 一个文件同时覆盖 http-request / http-response / cron|event 三种运行模式，
 * 附带 $argument 解析、$persistentStore 读写、$notification 推送、
 * $httpClient 请求与 $done 收尾的标准封装。
 *
 * 默认行为：**放行，不做任何修改**。所有会产生实际效果的逻辑都以注释态示例
 * 给出，复制本文件改名后取消对应注释即可。
 *
 * 在 .sgmodule 里的挂载方式（参见 modules/_template.sgmodule）：
 *   [Script]
 *   示例 = type=http-response,pattern=^https?://example\.com/api/,\
 *          requires-body=1,max-size=524288,timeout=10,\
 *          script-path=rules/scripts/_template.js,argument=debug=true&token=xxx
 *
 * 五条铁律（踩过就知道）：
 *   1. $done 必须、且只能被调用一次。任何分支、任何异常、任何回调都要走到它；
 *      漏掉 → 请求挂起直到脚本超时，用户侧表现为「网页转圈半天才失败」。
 *   2. 脚本超时由 [Script] 行的 timeout= 决定（默认 5 秒）。脚本内若发
 *      $httpClient 请求，timeout= 必须大于网络往返耗时，否则整段被掐断。
 *      给 $httpClient 自己也设一个更小的 timeout，留出收尾余量。
 *   3. 读 $request.body / $response.body 需要在 [Script] 行写 requires-body=1，
 *      否则拿到 undefined。二进制内容另需 binary-body-mode=true。
 *   4. $persistentStore.write(值, 键) —— 参数顺序是「值在前、键在后」，
 *      写反了不会报错，只会静默存错位置。值必须是字符串。
 *   5. 返回给 $done 的对象是「增量覆盖」：只写你要改的字段，
 *      没写的字段保持原样。返回 {} 即完全放行。
 *
 * 运行环境：Surge 内置 JavaScriptCore，支持 ES2017+（含 Promise / async）。
 * 无 Node.js API（没有 require / fs / Buffer），也没有浏览器 DOM。
 */

'use strict';

/* ═══════════════════════════════════════════════════════════════════════
 *  0. 基础常量
 * ═══════════════════════════════════════════════════════════════════════ */

/** 日志与通知里的标识名，改成你自己的脚本名。 */
const SCRIPT_NAME = 'Template';

/**
 * 持久化键名前缀。$persistentStore 是**全局共享**的键值空间，
 * 所有脚本挤在一起，不加前缀迟早互相覆盖。
 */
const STORE_PREFIX = 'template.';

/**
 * 调试开关：argument 里写 debug=true 即打开详细日志。
 * 这里先声明并给默认值，是为了让下面的 parseArgument() 在解析出错时
 * 也能安全地调用 log()（const 在赋值前处于暂时性死区，读它会直接抛错）。
 */
let DEBUG = false;

/* ═══════════════════════════════════════════════════════════════════════
 *  1. 运行模式判定
 * ═══════════════════════════════════════════════════════════════════════
 *  Surge 按脚本类型注入不同全局对象：
 *    http-request   → 只有 $request
 *    http-response  → $request + $response
 *    cron / event / generic → 两者都没有
 */

const IS_RESPONSE = typeof $response !== 'undefined' && $response !== null;
const IS_REQUEST = !IS_RESPONSE && typeof $request !== 'undefined' && $request !== null;
const IS_TIMER = !IS_RESPONSE && !IS_REQUEST;

/* ═══════════════════════════════════════════════════════════════════════
 *  2. $argument 解析
 * ═══════════════════════════════════════════════════════════════════════
 *  $argument 是 [Script] 行 argument= 后面那段原始字符串；
 *  未配置 argument= 时该全局变量不存在，必须用 typeof 保护。
 *
 *  支持两种写法：
 *    a) 查询串   token=abc&notify=true&interval=3600   （最常见）
 *    b) JSON     {"token":"abc","notify":true}         （值里有 & = 时更省事）
 */

/**
 * 把 $argument 解析成普通对象；解析失败一律回退空对象，绝不让脚本因此崩掉。
 * @param {string} raw 原始参数串
 * @returns {Object<string, string|boolean|number>}
 */
function parseArgument(raw) {
  if (typeof raw !== 'string' || raw.length === 0) return {};

  const text = raw.trim();
  if (text.charAt(0) === '{') {
    try {
      const parsed = JSON.parse(text);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (err) {
      log('argument JSON 解析失败，按空参数处理：' + err);
      return {};
    }
  }

  const out = {};
  text.split('&').forEach(function (pair) {
    if (!pair) return;
    const idx = pair.indexOf('=');
    const key = idx < 0 ? pair : pair.slice(0, idx);
    const val = idx < 0 ? '' : pair.slice(idx + 1);
    if (!key) return;
    try {
      out[decodeURIComponent(key)] = decodeURIComponent(val);
    } catch (err) {
      out[key] = val; // 值里有裸 % 时 decodeURIComponent 会抛，退化为原文
    }
  });
  return out;
}

/** 把 'true' / '1' / 'yes' / 'on' 视为真，其余为假。 */
function toBool(value, fallback) {
  if (value === undefined || value === null || value === '') return !!fallback;
  if (typeof value === 'boolean') return value;
  return /^(1|true|yes|on)$/i.test(String(value).trim());
}

/** 转整数，非法值回退默认。 */
function toInt(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

const ARGS = parseArgument(typeof $argument !== 'undefined' ? $argument : '');

DEBUG = toBool(ARGS.debug, false);

/* ═══════════════════════════════════════════════════════════════════════
 *  3. 工具封装
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * 日志。输出到 Surge「工具 → 脚本 → 脚本控制台」。
 * 关键错误始终打印；细节日志仅在 DEBUG 时打印，免得刷屏拖慢高频脚本。
 */
function log(message, verboseOnly) {
  if (verboseOnly && !DEBUG) return;
  console.log('[' + SCRIPT_NAME + '] ' + message);
}

/**
 * 系统通知。
 * options 可选：{ url: '点击跳转的链接', 'media-url': '配图', 'auto-dismiss': 10 }
 * 注意：高频的 http-* 脚本里别无脑推送，一次刷新几十条通知会被用户直接卸载。
 */
function notify(title, subtitle, body, options) {
  if (typeof $notification === 'undefined') return;
  try {
    if (options) {
      $notification.post(title, subtitle, body, options);
    } else {
      $notification.post(title, subtitle, body);
    }
  } catch (err) {
    log('通知发送失败：' + err);
  }
}

/**
 * 持久化存储。所有键自动加 STORE_PREFIX 前缀。
 * 底层 $persistentStore 只认字符串，对象请走 getJSON / setJSON。
 */
const store = {
  /** 读字符串；不存在或为空时返回 fallback。 */
  get: function (key, fallback) {
    try {
      const raw = $persistentStore.read(STORE_PREFIX + key);
      return raw === null || raw === undefined || raw === '' ? fallback : raw;
    } catch (err) {
      log('读取 ' + key + ' 失败：' + err);
      return fallback;
    }
  },

  /** 写字符串。⚠ 底层签名是 write(值, 键)，顺序别写反。 */
  set: function (key, value) {
    try {
      return $persistentStore.write(String(value), STORE_PREFIX + key);
    } catch (err) {
      log('写入 ' + key + ' 失败：' + err);
      return false;
    }
  },

  /** 读并 JSON.parse；损坏的旧数据不应让脚本崩掉，一律回退 fallback。 */
  getJSON: function (key, fallback) {
    const raw = this.get(key, null);
    if (raw === null) return fallback;
    try {
      return JSON.parse(raw);
    } catch (err) {
      log('解析 ' + key + ' 的 JSON 失败，已回退默认值：' + err);
      return fallback;
    }
  },

  /** JSON.stringify 后写入。 */
  setJSON: function (key, value) {
    try {
      return this.set(key, JSON.stringify(value));
    } catch (err) {
      log('序列化 ' + key + ' 失败：' + err);
      return false;
    }
  },

  /** 删除：写 null 即从存储中移除该键。 */
  remove: function (key) {
    try {
      return $persistentStore.write(null, STORE_PREFIX + key);
    } catch (err) {
      log('删除 ' + key + ' 失败：' + err);
      return false;
    }
  }
};

/**
 * $httpClient 的 Promise 封装。
 *
 * @param {'get'|'post'|'put'|'delete'|'head'|'patch'} method
 * @param {Object|string} options  字符串视为 url；对象形如
 *        { url, headers, body, timeout }（timeout 单位秒）
 * @returns {Promise<{status:number, headers:Object, body:string}>}
 *
 * ⚠ 这里的 timeout 是**网络请求**超时；它必须小于 [Script] 行的脚本 timeout=，
 *   否则脚本会先被 Surge 掐断，回调根本没机会执行，$done 也就永远不会被调用。
 */
function http(method, options) {
  return new Promise(function (resolve, reject) {
    const fn = $httpClient[method];
    if (typeof fn !== 'function') {
      reject(new Error('$httpClient 不支持方法：' + method));
      return;
    }
    const opts = typeof options === 'string' ? { url: options } : (options || {});
    if (!opts.url) {
      reject(new Error('缺少请求 url'));
      return;
    }
    fn(opts, function (error, response, data) {
      if (error) {
        reject(new Error(String(error)));
        return;
      }
      resolve({
        status: response ? (response.status || response.statusCode || 0) : 0,
        headers: (response && response.headers) || {},
        body: data
      });
    });
  });
}

/** JSON.parse 的安全版；解析失败返回 fallback 而不是抛出。 */
function safeJSON(text, fallback) {
  if (typeof text !== 'string' || text === '') return fallback;
  try {
    return JSON.parse(text);
  } catch (err) {
    log('JSON 解析失败：' + err, true);
    return fallback;
  }
}

/* ═══════════════════════════════════════════════════════════════════════
 *  4. $done 收尾（单次调用保护）
 * ═══════════════════════════════════════════════════════════════════════ */

let finished = false;

/**
 * 统一出口。无论成功、失败还是异常，最终都必须经过这里。
 * @param {Object} [result] 要覆盖的字段；不传或传 {} 表示完全放行。
 */
function finish(result) {
  if (finished) {
    log('检测到重复调用 $done，已忽略（请检查是否有分支漏了 return）');
    return;
  }
  finished = true;

  if (IS_TIMER) {
    // cron / event / generic：$done 不接受参数
    $done();
    return;
  }
  $done(result && typeof result === 'object' ? result : {});
}

/* ═══════════════════════════════════════════════════════════════════════
 *  5. http-request 处理
 * ═══════════════════════════════════════════════════════════════════════
 *  可读：$request.url / .method / .headers / .body（body 需 requires-body=1）
 *  可返回：
 *    {}                              放行
 *    { url }                         改写目标 URL
 *    { headers }                     替换请求头（是替换整个 headers 对象，
 *                                    要保留原有头就先 Object.assign 复制）
 *    { body }                        改写请求体
 *    { response: {status, headers, body} }
 *                                    直接伪造响应，真实请求不再发出
 */

function handleRequest(request) {
  log('→ ' + request.method + ' ' + request.url, true);

  // ── 示例 A：注入/删除请求头 ──────────────────────────────────────────
  // const headers = Object.assign({}, request.headers);
  // headers['X-Custom-Token'] = ARGS.token || '';
  // delete headers['Cookie'];
  // return { headers: headers };

  // ── 示例 B：去掉 URL 里的追踪参数 ────────────────────────────────────
  // const cleaned = request.url.replace(/([?&])(utm_[^&]*|fbclid=[^&]*)/g, '$1')
  //                            .replace(/[?&]$/, '');
  // if (cleaned !== request.url) return { url: cleaned };

  // ── 示例 C：改写请求体（需 requires-body=1）──────────────────────────
  // const payload = safeJSON(request.body, null);
  // if (payload) {
  //   payload.client = 'surge';
  //   return { body: JSON.stringify(payload) };
  // }

  // ── 示例 D：本地直接返回，拦掉这次请求 ───────────────────────────────
  //    比 [Map Local] 灵活（可按 header / body 内容动态决定），但开销更大；
  //    能用 [Map Local] 或 [URL Rewrite] 解决的就别写脚本。
  // return {
  //   response: {
  //     status: 200,
  //     headers: { 'Content-Type': 'application/json' },
  //     body: JSON.stringify({ ok: true })
  //   }
  // };

  return {}; // 默认：原样放行
}

/* ═══════════════════════════════════════════════════════════════════════
 *  6. http-response 处理
 * ═══════════════════════════════════════════════════════════════════════
 *  可读：$response.status / .headers / .body（body 需 requires-body=1）
 *        以及本次请求的 $request（拿 URL 做分支判断很常用）
 *  可返回：{} 放行 / { status } / { headers } / { body }
 */

function handleResponse(request, response) {
  const status = response.status || response.statusCode || 0;
  log('← ' + status + ' ' + request.url, true);

  // 非 2xx 一般不该再改 body，直接放行，避免把错误页改成假的成功页。
  // if (status < 200 || status >= 300) return {};

  // ── 示例 A：改 JSON 字段（解锁类脚本的典型写法）──────────────────────
  // const data = safeJSON(response.body, null);
  // if (!data) return {};                 // 解析失败必须放行，别返回半截 body
  // data.vip = true;
  // data.ads = [];
  // return { body: JSON.stringify(data) };

  // ── 示例 B：正则清理 HTML/JS 里的广告位 ──────────────────────────────
  // if (typeof response.body === 'string') {
  //   return { body: response.body.replace(/<div class="ad">[\s\S]*?<\/div>/g, '') };
  // }

  // ── 示例 C：改响应头 ─────────────────────────────────────────────────
  // const headers = Object.assign({}, response.headers);
  // headers['Cache-Control'] = 'no-store';
  // return { headers: headers };

  // ── 示例 D：读取响应内容后做记录 + 通知（不改 body）───────────────────
  // const info = safeJSON(response.body, {});
  // if (info.balance !== undefined && String(info.balance) !== store.get('balance', '')) {
  //   store.set('balance', info.balance);
  //   notify(SCRIPT_NAME, '余额变动', String(info.balance));
  // }
  // return {};

  return {}; // 默认：原样放行
}

/* ═══════════════════════════════════════════════════════════════════════
 *  7. cron / event / generic 处理
 * ═══════════════════════════════════════════════════════════════════════
 *  没有 $request / $response，纯粹主动执行。
 *  这类脚本几乎一定要发网络请求，务必把 [Script] 行的 timeout= 调够
 *  （例如 timeout=60），并且所有异步分支都要 return 出去交给 dispatcher。
 */

function handleTimer() {
  log('定时/事件任务触发');

  // ── 示例：签到并按需推送 ─────────────────────────────────────────────
  // const token = ARGS.token || store.get('token', '');
  // if (!token) {
  //   notify(SCRIPT_NAME, '未配置 token', '请在模块参数里填写后重试');
  //   return;                                   // 返回 undefined，dispatcher 会收尾
  // }
  //
  // const today = new Date().toISOString().slice(0, 10);
  // if (store.get('lastCheckin', '') === today) {
  //   log('今日已签到，跳过');
  //   return;
  // }
  //
  // return http('post', {
  //   url: 'https://example.com/api/checkin',
  //   headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
  //   body: JSON.stringify({ source: 'surge' }),
  //   timeout: toInt(ARGS.timeout, 15)          // 必须小于 [Script] 的 timeout=
  // }).then(function (res) {
  //   const data = safeJSON(res.body, {});
  //   if (res.status === 200 && data.ok) {
  //     store.set('lastCheckin', today);
  //     if (toBool(ARGS.notify, true)) notify(SCRIPT_NAME, '签到成功', data.message || '');
  //   } else {
  //     notify(SCRIPT_NAME, '签到失败', 'HTTP ' + res.status);
  //   }
  // });
  // 注意：上面这条 return 把 Promise 交给 dispatcher，由它统一 catch 并调用 $done。
  //      千万别在 .then 里自己再调一次 $done。

  return undefined; // 默认：什么都不做
}

/* ═══════════════════════════════════════════════════════════════════════
 *  8. 入口分发
 * ═══════════════════════════════════════════════════════════════════════
 *  同步返回值与 Promise 都能处理；任何异常都兜底放行并调用 $done，
 *  保证请求不会因为脚本报错而卡到超时。
 */

function main() {
  if (IS_RESPONSE) return handleResponse($request, $response);
  if (IS_REQUEST) return handleRequest($request);
  return handleTimer();
}

try {
  Promise.resolve(main())
    .then(function (result) {
      finish(result);
    })
    .catch(function (err) {
      log('异步异常，已放行：' + err);
      finish({});
    });
} catch (err) {
  log('同步异常，已放行：' + err);
  finish({});
}
