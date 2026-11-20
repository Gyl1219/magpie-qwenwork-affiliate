// src/growth.mjs —— 千问办公推广渠道归因（纯函数）
//
// 这个模块只回答四个问题：
//   ① 渠道名 / 链接 / 安装包文件名里，能取出哪个 attribution_id？
//   ② 怎么把它追加到官方 PC 客户端的登录 URL 上？
//   ③ 这条渠道对应的安装包文件名长什么样（仅展示/解析）？
//   ④ 官方增长事件的信封怎么构造？
//
// 它**不**发网络请求、**不**生成 baxia 风控头、**不**签名、**不**自动上报。
// 官方登录页 / 客户端里的 bx-ua、bx-umidtoken、bx_et 由阿里 baxia SDK 在
// 浏览器内生成，离线既无法复算，也不应该伪造；本模块只把「渠道」拼进
// 官方登录 URL，真正的上报交给官方页面完成。
//
// 事实边界（与官网 tracking bundle 的 p 正则逐字一致）：
//   · attribution_id 白名单是 /^[a-zA-Z0-9_-]{1,64}$/；
//   · event_id 是另一个字段（UUID），与 attribution_id 从不同处取值，不互相冒充；
//   · xingdoukejiDownload162 是合法渠道名，但渠道名本身不是签名；
//   · 安装包文件名由 CDN 的 response-content-disposition 决定，服务端不做校验，
//     所以文件名只能当展示/解析标签，不能当「服务端已确认归属」的证据；
//   · website 是官网直发哨兵，不是推广渠道，不追加 affiliate 参数。

/** 官方 attribution_id 白名单（1–64 位字母 / 数字 / 下划线 / 连字符） */
export const ATTRIBUTION_RE = /^[a-zA-Z0-9_-]{1,64}$/

/** 官网直发哨兵：它表示「没有推广渠道」，不是一条可上报的渠道 */
const WEBSITE_CHANNEL = "website"

/** event_id 是规范 UUID；attribution_id 不是 UUID，两者字段与校验都分开 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** 本模块只构造这三种官方增长事件；落地/下载/订单/支付事件不在这里伪造 */
const EVENT_TYPES = new Set(["login_succeeded", "registration_succeeded", "conversation_started"])

/** 每种事件 data 里官方允许的字段（严格白名单，避免把凭据塞进上报体） */
const DATA_FIELDS = {
  login_succeeded: ["user_id"],
  registration_succeeded: ["user_id"],
  conversation_started: ["conversation_id", "user_id"],
}

/** 官方对 user_id / device_id 的约束：UTF-8 ≤ 2048 字节、非空、不含控制字符 */
const MAX_FIELD_BYTES = 2048

/** 输入长度上限：渠道名只有 64，正常链接远小于 4 KiB；超长直接拒绝 */
const MAX_INPUT_CHARS = 4096
const MAX_LOGIN_URL_CHARS = 8192

/** 管理键：追加登录 URL 时先删掉旧值，避免重复参数 */
const MANAGED_KEYS = new Set([
  "utm_source",
  "utm_medium",
  "utm_campaign",
  "attribution_id",
  "origin_client_type",
])

/** parseAttribution 可能返回的 source；withAttribution 收解析结果时用它回填 */
const SOURCES = new Set(["none", "channel", "attribution_id", "affiliate", "download"])

/** 凭据类 query 键（精确匹配；state / code_challenge 是 PKCE 协议参数，不在此列） */
const CREDENTIAL_KEYS = new Set([
  "authorization",
  "auth",
  "bearer",
  "access_token",
  "refresh_token",
  "id_token",
  "token",
  "password",
  "passwd",
  "pwd",
  "secret",
  "client_secret",
  "api_key",
  "apikey",
  "session",
  "sessionid",
  "session_id",
  "cookie",
  "code",
  "code_verifier",
  "email",
  "phone",
  "mobile",
  "credential",
  "credentials",
])

/** 一眼像凭据的值：不让它们被当成渠道名写进 URL / 日志 */
const SECRET_VALUE = [
  /^Bearer\s+\S+/i,
  /^Basic\s+\S+/i,
  /^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, // JWT
  /^sk-[A-Za-z0-9_-]{16,}$/,
  /^gh[pousr]_[A-Za-z0-9]{20,}$/,
  /^xox[abpr]-[A-Za-z0-9-]{10,}$/,
  /^AKIA[0-9A-Z]{16}$/,
  /^AIza[0-9A-Za-z_-]{35}$/,
]

/** 控制字符（含 C1 与 Unicode 行分隔符）：出现在 URL / 文件名 / 字段里一律拒绝 */
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/

/** 同一张表，仅在错误文本里做「全部替换」用（带 g 的 test 会带状态，不能混用） */
const CONTROL_G = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g

/** 解析 / 构造归因时的显式错误；`code` 让调用方和测试能分流 */
export class GrowthError extends Error {
  constructor(message, { code = "invalid_attribution", field = "" } = {}) {
    super(message)
    this.name = "GrowthError"
    this.code = code
    this.field = field
  }
}

function fail(message, code, field) {
  throw new GrowthError(message, { code, field })
}

/** 错误文本里出现 URL 时抹掉 userinfo；控制字符换成 ?，再截断 */
function safeText(value) {
  return String(value ?? "")
    .replace(/\/\/[^/\s]*@/g, "//***@")
    .replace(CONTROL_G, "?")
    .slice(0, 160)
}

/** 报「URL 不合法」时只显示到 path：query / fragment 里可能有 token，不回显 */
function describeUrl(value) {
  const text = String(value ?? "")
  const cut = text.search(/[?#]/)
  return safeText(cut >= 0 ? text.slice(0, cut) : text)
}

function assertNoControl(value, field) {
  if (CONTROL_RE.test(String(value))) {
    fail(`${field} 不能包含换行、NUL 等控制字符`, "invalid_input", field)
  }
}

function assertLength(value, max, field) {
  const text = String(value)
  if (text.length > max) {
    fail(`${field} 超过 ${max} 个字符，拒绝继续解析`, "invalid_input", field)
  }
}

function byteLength(value) {
  return new TextEncoder().encode(String(value)).length
}

/** 空归因：每次都返回新对象，避免调用方改到别人手里的结果 */
function noneResult() {
  return { attributionId: "", originClientType: "pc", source: "none" }
}

function isSecretLike(value) {
  const text = String(value ?? "").trim()
  return SECRET_VALUE.some((re) => re.test(text))
}

function isCredentialKey(raw) {
  const key = String(raw ?? "").trim().toLowerCase().replace(/-/g, "_")
  if (CREDENTIAL_KEYS.has(key)) return true
  return /^(?:.*_)?(?:token|secret|password|api_key|authorization|cookie)$/.test(key)
}

function isQwenworkHost(host) {
  const name = String(host ?? "").toLowerCase()
  return name === "qwenwork.cn" || name.endsWith(".qwenwork.cn")
}

function basenameOf(value) {
  const text = String(value ?? "")
  const cut = Math.max(text.lastIndexOf("/"), text.lastIndexOf("\\"))
  return cut >= 0 ? text.slice(cut + 1) : text
}

function isInstallerFilename(value) {
  // 只做「像不像官方安装包」的路由；严格格式由 parseInstallerFilename 判
  return /(?:^|[\\/])qwenworkcn-[^\\/]*\.(?:exe|dmg|deb)$/i.test(String(value ?? "").trim())
}

/** 把「渠道名」变成统一返回值；website 是哨兵，按无渠道处理 */
function channelResult(raw, source) {
  const original = String(raw ?? "")
  // 先查原始值：trim 会吃掉两端的 CR/LF，不能靠 trim 后的结果判断注入
  if (CONTROL_RE.test(original)) {
    fail("渠道标识不能包含换行、NUL 等控制字符", "invalid_input", "attributionId")
  }
  const id = original.trim()
  if (!id) fail("渠道标识不能为空", "invalid_attribution", "attributionId")
  if (isSecretLike(id)) {
    fail("这段字符串看起来是凭据，不是渠道标识；拒绝写进归因参数", "credential", "attributionId")
  }
  if (!ATTRIBUTION_RE.test(id)) {
    fail(
      `渠道标识只能是 1–64 位字母、数字、下划线或连字符（/^[a-zA-Z0-9_-]{1,64}$/），收到：${safeText(id)}`,
      "invalid_attribution",
      "attributionId"
    )
  }
  if (id.toLowerCase() === WEBSITE_CHANNEL) return noneResult()
  return { attributionId: id, originClientType: "pc", source }
}

/** URL 参数同名多值且不一致时拒绝猜测（防参数注入 / 归因串号） */
function singleParam(url, key) {
  const rawValues = url.searchParams.getAll(key)
  for (const value of rawValues) {
    if (CONTROL_RE.test(value)) {
      fail(`URL 参数 ${key} 含换行、NUL 等控制字符`, "url_injection", key)
    }
  }
  const values = rawValues.map((v) => v.trim())
  if (values.length === 0) return undefined
  if (new Set(values).size > 1) {
    fail(`URL 里出现多个取值不同的 ${key}，拒绝猜测`, "url_injection", key)
  }
  return values[0]
}

/** 响应头里的百分号编码可能被原样传进来；只在确实像编码头时才解码 */
function decodeHeaderIfNeeded(text) {
  const raw = String(text ?? "")
  if (!/%3b|%3d/i.test(raw)) return raw
  try {
    return decodeURIComponent(raw)
  } catch {
    fail("response-content-disposition 的百分号编码损坏", "invalid_input", "content-disposition")
  }
}

/** 解析 attachment;filename=qwenworkcn-<渠道>_setup-<arch>.exe */
function parseDisposition(value) {
  const text = decodeHeaderIfNeeded(value).trim()
  if (!text) fail("response-content-disposition 为空", "invalid_input", "content-disposition")

  let filename
  const star = /(?:^|;)\s*filename\*\s*=\s*(?:UTF-8''|utf-8'')?([^;]+)/i.exec(text)
  if (star) {
    try {
      filename = decodeURIComponent(String(star[1]).trim().replace(/^"(.*)"$/, "$1"))
    } catch {
      fail("response-content-disposition 的 filename* 编码损坏", "invalid_input", "content-disposition")
    }
  } else {
    const plain = /(?:^|;)\s*filename\s*=\s*(?:"([^"]*)"|([^;]*))/i.exec(text)
    if (plain) filename = String(plain[1] ?? plain[2] ?? "").trim()
  }

  if (!filename) {
    fail(`response-content-disposition 里没有 filename：${safeText(text)}`, "invalid_input", "content-disposition")
  }
  return parseInstallerFilename(filename, "download")
}

/** 官方安装包文件名：qwenworkcn-<渠道>_setup-<arch>.exe（或官网默认无渠道名） */
function parseInstallerFilename(filename, source) {
  const original = String(filename ?? "")
  if (CONTROL_RE.test(original)) {
    fail("安装包文件名不能包含换行、NUL 等控制字符", "invalid_input", "filename")
  }
  const name = basenameOf(original.trim())
  if (!name) fail("安装包文件名为空", "invalid_input", "filename")

  const labeled = /^qwenworkcn-(.+)_setup-(?:x64|arm64)\.(?:exe|dmg|deb)$/i.exec(name)
  if (labeled) return channelResult(labeled[1], source)

  if (/^qwenworkcn-setup-(?:x64|arm64)\.(?:exe|dmg|deb)$/i.test(name)) return noneResult()

  fail(`不是千问办公官方安装包文件名：${safeText(name)}`, "invalid_attribution", "filename")
}

/** 解析绝对 URL（只接受 qwenwork.cn 系 https 链接） */
function parseUrl(raw) {
  let url
  try {
    url = new URL(raw)
  } catch {
    fail(`不是合法的绝对 URL：${describeUrl(raw)}`, "invalid_url", "input")
  }
  if (url.protocol !== "https:") {
    fail(`只接受 https 链接，实际协议是 ${url.protocol}`, "invalid_url", "input")
  }
  if (url.username || url.password) {
    fail("链接里不允许携带 userinfo 凭据（账号或口令）", "credential", "input")
  }

  const host = url.hostname.toLowerCase()
  if (!isQwenworkHost(host)) {
    fail(`只接受 qwenwork.cn 及其子域名的链接，实际主机是 ${safeText(host)}`, "url_injection", "input")
  }

  for (const key of url.searchParams.keys()) {
    if (isCredentialKey(key)) {
      fail(`链接里不允许携带凭据参数（${safeText(key)}）`, "credential", "input")
    }
  }

  // 本模块代表 PC 客户端：输入里的 origin_client_type 只做格式校验，输出固定 pc
  const originClientType = singleParam(url, "origin_client_type")
  if (originClientType !== undefined && !/^(?:pc|web)$/i.test(originClientType)) {
    fail("origin_client_type 只允许 pc 或 web", "invalid_input", "origin_client_type")
  }

  // 优先级：显式 attribution_id > affiliate 三元组 > 下载文件名标签。
  // 文件名只是链接级展示，服务端不校验，所以放在最后。
  const attributionId = singleParam(url, "attribution_id")
  if (attributionId !== undefined) {
    if (!attributionId) {
      fail("attribution_id 参数存在但为空", "invalid_attribution", "attribution_id")
    }
    return channelResult(attributionId, "attribution_id")
  }

  // 官方客户端三元组：utm_source=affiliate & utm_medium=<channel> & utm_campaign=online。
  // 官网 /signin 的网页规则还要求 utm_medium 形如 ad+12 位；但客户端非 website
  // 渠道直接拿渠道名当 medium（如 xingdoukejiDownload162），所以这里按统一白名单收。
  const source = singleParam(url, "utm_source")
  const medium = singleParam(url, "utm_medium")
  const campaign = singleParam(url, "utm_campaign")
  if (source === "affiliate") {
    if (campaign !== "online") {
      fail("affiliate 三元组的 utm_campaign 必须是 online", "invalid_attribution", "utm_campaign")
    }
    if (!medium) {
      fail("affiliate 三元组缺少 utm_medium", "invalid_attribution", "utm_medium")
    }
    return channelResult(medium, "affiliate")
  }

  // 下载链接：response-content-disposition 优先于路径里的文件名
  if (host === "assets.qwenwork.cn") {
    const disposition = singleParam(url, "response-content-disposition")
    if (disposition !== undefined) return parseDisposition(disposition)

    const name = basenameOf(url.pathname)
    if (isInstallerFilename(name)) return parseInstallerFilename(name, "download")
  }

  return noneResult()
}

/**
 * 解析渠道归因。
 *
 * 支持：直接渠道字符串、带 attribution_id 的 qwenwork URL、affiliate 三元组 URL、
 * assets.qwenwork.cn 下载 URL、response-content-disposition（头值 / URL 参数值）、
 * 官方安装包文件名。空输入返回 `{attributionId:"", originClientType:"pc", source:"none"}`。
 *
 * `source` 的取值：`none` / `channel`（直接渠道名）/ `attribution_id`（URL 参数）/
 * `affiliate`（UTM 三元组）/ `download`（下载链接或文件名）。`download` 只说明
 * 这个值来自链接级文件名标签，不代表服务端已确认归属。
 *
 * @param {string|URL|null|undefined} input
 * @returns {{attributionId: string, originClientType: "pc", source: string}}
 */
export function parseAttribution(input) {
  if (input === undefined || input === null) return noneResult()

  if (input instanceof URL) {
    assertLength(input.href, MAX_INPUT_CHARS, "input")
    return parseUrl(input.href)
  }

  if (typeof input !== "string") {
    fail(`parseAttribution 只接受字符串、URL 或空值，收到 ${typeof input}`, "invalid_input", "input")
  }

  assertLength(input, MAX_INPUT_CHARS, "input")
  const raw = input.trim()
  if (!raw) return noneResult()
  // 空串 / 纯空白已经在上面归到 none；剩下的输入里出现控制字符一律按注入拒绝
  assertNoControl(input, "input")

  // Windows 盘符路径不是 URL（`C:\...` 会被 URL 解析器当成 c: 协议）
  if (/^[a-zA-Z]:[\\/]/.test(raw)) {
    if (isInstallerFilename(raw)) return parseInstallerFilename(raw, "download")
    fail(`不是千问办公官方安装包路径：${safeText(raw)}`, "invalid_attribution", "filename")
  }

  // 绝对 URL / 协议相对 URL 先交给 URL 解析器，避免把 query 里的 filename= 误当响应头
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.startsWith("//")) return parseUrl(raw)

  const header = decodeHeaderIfNeeded(raw)
  if (/^(?:attachment|inline)\b/i.test(header) || /(?:^|;)\s*filename\*?\s*=/i.test(header)) {
    return parseDisposition(header)
  }

  if (isInstallerFilename(raw)) return parseInstallerFilename(raw, "download")

  return channelResult(raw, "channel")
}

/** 登录 URL 的闸门：改之前确认它确实是 qwenwork 的 https 链接，且没夹带凭据 */
function assertLoginUrl(href) {
  let url
  try {
    url = new URL(href)
  } catch {
    fail(`loginUrl 不是合法的绝对 URL：${describeUrl(href)}`, "invalid_url", "loginUrl")
  }
  if (url.protocol !== "https:") {
    fail(`loginUrl 必须是 https，实际协议是 ${url.protocol}`, "invalid_url", "loginUrl")
  }
  if (url.username || url.password) {
    fail("loginUrl 里不允许携带 userinfo 凭据（账号或口令）", "credential", "loginUrl")
  }
  if (!isQwenworkHost(url.hostname)) {
    fail(`loginUrl 必须是 qwenwork.cn 及其子域名，实际主机是 ${safeText(url.hostname)}`, "url_injection", "loginUrl")
  }
  for (const key of url.searchParams.keys()) {
    if (isCredentialKey(key)) {
      fail(`loginUrl 里不允许携带凭据参数（${safeText(key)}）`, "credential", "loginUrl")
    }
  }
}

function decodeKey(raw) {
  try {
    return decodeURIComponent(String(raw).replace(/\+/g, " "))
  } catch {
    return String(raw)
  }
}

/** 保留原 query 的顺序与编码，只删掉本模块管理的 5 个键，再把新值追加到末尾 */
function appendQuery(href, params) {
  const hashAt = href.indexOf("#")
  const beforeHash = hashAt >= 0 ? href.slice(0, hashAt) : href
  const hash = hashAt >= 0 ? href.slice(hashAt) : ""

  const queryAt = beforeHash.indexOf("?")
  const head = queryAt >= 0 ? beforeHash.slice(0, queryAt) : beforeHash
  const rawQuery = queryAt >= 0 ? beforeHash.slice(queryAt + 1) : ""

  const kept = []
  for (const segment of rawQuery.split("&")) {
    if (!segment) continue
    const eq = segment.indexOf("=")
    const key = decodeKey(eq >= 0 ? segment.slice(0, eq) : segment)
    if (MANAGED_KEYS.has(key)) continue
    kept.push(segment)
  }
  for (const [key, value] of params) {
    kept.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
  }

  return `${head}?${kept.join("&")}${hash}`
}

/** withAttribution 也接受 parseAttribution 的返回值：校验后只取其中的渠道 ID */
function attributionOfInput(input) {
  if (
    input === null ||
    typeof input !== "object" ||
    input instanceof URL ||
    Array.isArray(input) ||
    !Object.prototype.hasOwnProperty.call(input, "attributionId") ||
    typeof input.attributionId !== "string"
  ) {
    return parseAttribution(input)
  }

  const id = input.attributionId
  if (!id.trim()) return noneResult()
  const source = SOURCES.has(input.source) ? input.source : "channel"
  return channelResult(id, source)
}

/** 官方桌面分发渠道规范化：小写、非法字符转为下划线，空值回退 website。 */
export function normalizeDistributionChannel(value) {
  const raw = String(value ?? "").trim()
  if (!raw || raw.toLowerCase() === "website") return "website"
  return raw.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "website"
}

/**
 * 按官方 PC 客户端的两段式登录构造渠道入口。
 * 原设备申请 URL 完整放进 oauth_callback；外层 /users/sign-in 携带
 * biz_variant=qoderwork 与 affiliate 三元组。无渠道 / website 时原样返回。
 */
export function withAttribution(loginUrl, input) {
  const parsed = attributionOfInput(input)
  const channel = normalizeDistributionChannel(parsed.attributionId)
  if (channel === "website") {
    return loginUrl instanceof URL ? loginUrl.href : String(loginUrl ?? "")
  }

  const href = loginUrl instanceof URL ? loginUrl.href : String(loginUrl ?? "")
  if (!href.trim()) fail("loginUrl 不能为空", "invalid_url", "loginUrl")
  assertNoControl(href, "loginUrl")
  assertLength(href, MAX_LOGIN_URL_CHARS, "loginUrl")
  assertLoginUrl(href)

  // 与桌面端 buildQoderWorkLoginUrl 同构：设备申请 URL 保持白名单，
  // 外层 /users/sign-in 读取渠道后，再 302 回 oauth_callback。
  const callback = new URL(href)
  for (const key of MANAGED_KEYS) callback.searchParams.delete(key)
  callback.searchParams.delete("biz_variant")
  const outer = new URL("/users/sign-in", callback.origin)
  outer.searchParams.set("biz_variant", "qoderwork")
  outer.searchParams.set("utm_source", "affiliate")
  outer.searchParams.set("utm_medium", channel)
  outer.searchParams.set("utm_campaign", "online")
  outer.searchParams.set("oauth_callback", callback.toString())
  return outer.toString()
}

/**
 * 生成安装包展示文件名。只用于展示 / 解析，不代表服务端归因。
 *
 * input 为空 → `qwenworkcn-setup-<arch>.exe`；有渠道 →
 * `qwenworkcn-<channel>_setup-<arch>.exe`。文件名不是签名，服务端也不校验它。
 *
 * @param {string|URL|null|undefined} input
 * @param {"x64"|"arm64"} [arch]
 * @returns {string}
 */
export function downloadFilename(input, arch = "x64") {
  const build = String(arch ?? "").trim().toLowerCase()
  if (build !== "x64" && build !== "arm64") {
    fail(`arch 只支持 x64 / arm64，收到：${safeText(arch)}`, "unsupported_arch", "arch")
  }

  const { attributionId } = attributionOfInput(input)
  if (!attributionId) return `qwenworkcn-setup-${build}.exe`
  return `qwenworkcn-${attributionId}_setup-${build}.exe`
}

function requireField(value, field, code = "invalid_data") {
  if (value === undefined || value === null) fail(`${field} 必填`, code, field)
  if (typeof value !== "string") fail(`${field} 必须是字符串`, code, field)
  if (!value.trim()) fail(`${field} 不能是空白`, code, field)
  if (CONTROL_RE.test(value)) fail(`${field} 不能包含控制字符`, code, field)
  if (byteLength(value) > MAX_FIELD_BYTES) {
    fail(`${field} 超过官方上限 ${MAX_FIELD_BYTES} 字节`, code, field)
  }
  return value
}

function optionalField(value, field) {
  if (value === undefined || value === null || value === "") return undefined
  return requireField(value, field)
}

/**
 * 构造官方增长事件信封（纯对象，不发送、不伪造 bx 头）。
 *
 * 只允许 login_succeeded / registration_succeeded / conversation_started。
 * `eventId` 是 UUID 字段；`attributionId` 是渠道字段，两者不互相推导。
 *
 * @param {{
 *   eventType: string,
 *   eventId: string,
 *   attributionId: string,
 *   userId: string,
 *   deviceId?: string,
 *   originClientType?: "pc"|"web",
 *   data?: object,
 * }} input
 * @returns {object}
 */
export function buildGrowthEvent({
  eventType,
  eventId,
  attributionId,
  userId,
  deviceId,
  originClientType = "pc",
  data,
} = {}) {
  if (!EVENT_TYPES.has(eventType)) {
    fail(
      `eventType 只允许 ${[...EVENT_TYPES].join(" / ")}；${safeText(eventType)} 不是本模块可构造的事件`,
      "unsupported_event",
      "eventType"
    )
  }

  const event = requireField(eventId, "eventId", "invalid_event")
  if (!UUID_RE.test(event)) {
    fail("eventId 必须是规范 UUID（8-4-4-4-12）", "invalid_event", "eventId")
  }

  const id = requireField(attributionId, "attributionId", "invalid_attribution")
  if (isSecretLike(id)) {
    fail("attributionId 看起来是凭据，不是渠道标识", "credential", "attributionId")
  }
  if (!ATTRIBUTION_RE.test(id)) {
    fail(
      `attributionId 只能是 1–64 位字母、数字、下划线或连字符（/^[a-zA-Z0-9_-]{1,64}$/）`,
      "invalid_attribution",
      "attributionId"
    )
  }
  if (id.toLowerCase() === WEBSITE_CHANNEL) {
    fail("website 是官网直发哨兵，不是可上报的推广渠道", "invalid_attribution", "attributionId")
  }

  const user = requireField(userId, "userId")
  const device = optionalField(deviceId, "deviceId")

  const origin = String(originClientType ?? "").trim().toLowerCase()
  if (origin !== "pc" && origin !== "web") {
    fail("originClientType 只允许 pc 或 web", "invalid_input", "originClientType")
  }

  const extra = data === undefined || data === null ? {} : data
  if (typeof extra !== "object" || Array.isArray(extra)) {
    fail("data 必须是对象", "invalid_data", "data")
  }

  const allowed = DATA_FIELDS[eventType]
  for (const key of Object.keys(extra)) {
    if (!allowed.includes(key)) {
      fail(
        `${eventType} 的 data 只允许 ${allowed.join(" / ")}，不允许 ${safeText(key)}`,
        "invalid_data",
        "data"
      )
    }
  }
  if (Object.prototype.hasOwnProperty.call(extra, "user_id") && extra.user_id !== user) {
    fail("data.user_id 与 userId 不一致；不要用 data 覆盖用户身份", "invalid_data", "data.user_id")
  }

  let conversationId
  if (eventType === "conversation_started") {
    conversationId = requireField(extra.conversation_id, "data.conversation_id")
  }

  return {
    event_id: event,
    event_type: eventType,
    ...(device === undefined ? {} : { device_id: device }),
    attribution_id: id,
    context: { client_type: "pc", origin_client_type: origin },
    data:
      conversationId === undefined
        ? { user_id: user }
        : { conversation_id: conversationId, user_id: user },
  }
}