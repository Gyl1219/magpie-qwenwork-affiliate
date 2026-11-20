import { readFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { accountLabelOf } from "./account-name.mjs"

const SOURCE_AGENT = "plugin:qwenwork"
const TARGET_AGENT = "plugin:qwenwork-affiliate"

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

export function discoverQwenWorkAccounts({ configDir = path.join(os.homedir(), ".config", "magpie"), readFile = readFileSync } = {}) {
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
    unique.set(uid, { uid, label: qwenWorkDisplayName(credential), credential: structuredClone(credential) })
  }
  return [...unique.values()]
}

export function createQwenWorkReuseMethods({ attributionId, ...options } = {}) {
  const channel = String(attributionId ?? "").trim()
  return discoverQwenWorkAccounts(options).map(({ uid, label, credential }) => ({
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
          return {
            ...structuredClone(credential),
            type: "success",
            accountId: label,
            cardName: label,
            uid,
            attributionId: channel,
          }
        },
      }
    },
  }))
}
