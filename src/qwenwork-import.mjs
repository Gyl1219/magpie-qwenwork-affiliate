import { readFileSync, renameSync, writeFileSync } from "node:fs"
import { randomUUID } from "node:crypto"
import os from "node:os"
import path from "node:path"
import { accountLabelOf } from "./account-name.mjs"

const SOURCE_AGENT = "plugin:qwenwork"
const TARGET_AGENT = "plugin:qwenwork-affiliate"
const TOKEN_FIELDS = ["type", "refresh", "access", "expires", "deviceChat", "machineId", "deviceToken", "deviceRefresh"]

function configDirOf(options) {
  return options?.configDir ?? path.join(os.homedir(), ".config", "magpie")
}

function readJson(readFile, file) {
  try {
    const value = JSON.parse(readFile(file, "utf8"))
    return value && typeof value === "object" ? value : null
  } catch {
    return null
  }
}

export function qwenWorkDisplayName(auth) {
  const explicit = String(auth?.cardName ?? auth?.phoneLabel ?? "").trim()
  if (explicit) return explicit
  const email = String(auth?.email ?? "").trim()
  return accountLabelOf(
    { ...auth, email: email.endsWith("@phone.local") ? "" : email },
    { mobile: ["cardName", "phoneLabel", "maskedMobile", "mobile", "phone", "phoneNumber"], id: ["name"] },
  ) || "已登录账号"
}

export function discoverQwenWorkAccounts(options = {}) {
  const { readFile = readFileSync } = options
  const configDir = configDirOf(options)
  const auth = readJson(readFile, path.join(configDir, "plugin-auth.json"))
  if (!auth) return []
  const loginRows = readJson(readFile, path.join(configDir, "logins.json"))
  const rows = Array.isArray(loginRows) ? loginRows : []
  const imported = new Set(
    rows
      .filter((row) => row?.agent === TARGET_AGENT)
      .map((row) => auth[row.home]?.uid)
      .filter(Boolean),
  )
  for (const [home, credential] of Object.entries(auth)) {
    if (home === "qwenwork-affiliate" || home.startsWith("qwenwork-affiliate#")) {
      if (credential?.uid) imported.add(credential.uid)
    }
  }
  const sourceHomes = rows.length > 0
    ? rows.filter((row) => row?.agent === SOURCE_AGENT).map((row) => row.home).filter(Boolean)
    : Object.keys(auth).filter((home) => home === "qwenwork" || home.startsWith("qwenwork#"))

  const unique = new Map()
  for (const home of sourceHomes) {
    const credential = auth[home]
    const uid = String(credential?.uid ?? "").trim()
    if (!credential || (!credential.access && !credential.refresh) || !uid || imported.has(uid) || unique.has(uid)) continue
    unique.set(uid, { home, uid, label: qwenWorkDisplayName(credential), credential: structuredClone(credential) })
  }
  return [...unique.values()]
}

export function latestQwenWorkCredential(uid, options = {}) {
  const id = String(uid ?? "").trim()
  if (!id) return null
  const auth = readJson(options.readFile ?? readFileSync, path.join(configDirOf(options), "plugin-auth.json"))
  if (!auth) return null
  const candidates = Object.entries(auth)
    .filter(([home, credential]) => (home === "qwenwork" || home.startsWith("qwenwork#") || home === "qwenwork-affiliate" || home.startsWith("qwenwork-affiliate#")) && credential?.uid === id && credential?.access && credential?.refresh)
    .sort((a, b) => Number(b[1].expires ?? 0) - Number(a[1].expires ?? 0))
  return candidates[0] ? { home: candidates[0][0], credential: structuredClone(candidates[0][1]) } : null
}

export function syncQwenWorkCredentialFamily({ uid, previous, refreshed, ...options } = {}) {
  const id = String(uid ?? "").trim()
  if (!id || !previous || !refreshed) return { updated: 0, skipped: 0 }
  const configDir = configDirOf(options)
  const authFile = path.join(configDir, "plugin-auth.json")
  const auth = readJson(options.readFile ?? readFileSync, authFile)
  if (!auth) return { updated: 0, skipped: 0 }
  let updated = 0
  let skipped = 0
  for (const [home, credential] of Object.entries(auth)) {
    if (!(home === "qwenwork" || home.startsWith("qwenwork#") || home === "qwenwork-affiliate" || home.startsWith("qwenwork-affiliate#")) || credential?.uid !== id) continue
    const independentlyRefreshed = Number(credential.expires ?? 0) > Number(previous.expires ?? 0)
      && (credential.access !== previous.access || credential.refresh !== previous.refresh)
    if (independentlyRefreshed) { skipped++; continue }
    for (const field of TOKEN_FIELDS) {
      if (refreshed[field] !== undefined) credential[field] = refreshed[field]
    }
    updated++
  }
  if (updated > 0) {
    const temp = `${authFile}.${process.pid}-${randomUUID()}.tmp`
    ;(options.writeFile ?? writeFileSync)(temp, JSON.stringify(auth, null, 2) + "\n", { mode: 0o600 })
    ;(options.renameFile ?? renameSync)(temp, authFile)
  }
  return { updated, skipped }
}

export function createQwenWorkReuseMethods({ attributionId, ...options } = {}) {
  const channel = String(attributionId ?? "").trim()
  const readFile = options.readFile ?? readFileSync
  const configDir = configDirOf(options)
  return discoverQwenWorkAccounts(options).map(({ home, uid, label }) => ({
    type: "oauth",
    label: `Reuse QwenWork · ${label}`,
    prompts: [],
    async authorize() {
      return {
        url: "",
        opened: true,
        method: "auto",
        instructions: "直接复用本机已有 QwenWork 登录，添加后可自动领取基础会员。",
        async callback() {
          // 从发现到点击之间，原 provider 可能已经轮换过 token；必须读最新值。
          const latest = readJson(readFile, path.join(configDir, "plugin-auth.json"))?.[home]
          if (!latest || latest.uid !== uid || (!latest.access && !latest.refresh)) {
            return { type: "failed", message: "原 QwenWork 凭据已变化，请重新打开账号复用入口" }
          }
          const currentLabel = qwenWorkDisplayName(latest)
          return {
            ...structuredClone(latest),
            type: "success",
            accountId: currentLabel,
            cardName: currentLabel,
            uid,
            attributionId: channel,
          }
        },
      }
    },
  }))
}
