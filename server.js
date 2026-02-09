#!/usr/bin/env node
"use strict";

const http = require("http");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawn } = require("child_process");
let nodemailer = null;
try {
  // Optional dependency used for email verification.
  nodemailer = require("nodemailer");
} catch {
  // Ignore.
}

const PORT = Number(process.env.PORT || 5173);
const HOST = process.env.HOST || "0.0.0.0";
const VIDEO_DIR = path.resolve(process.env.VIDEO_DIR || path.join(process.cwd(), "videos"));
const INDEX_FILE = path.resolve(process.cwd(), "index.html");
// Legacy shared token (pre-accounts). If provided and matched via ?token=..., it grants full access.
const LEGACY_TOKEN = String(process.env.TOKEN || "");

const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(process.cwd(), ".camfordick-data"));
const CACHE_DIR = path.resolve(process.env.CACHE_DIR || path.join(process.cwd(), ".camfordick-cache"));

const PREVIEW_SECONDS = Math.max(1, Math.min(60, Number(process.env.PREVIEW_SECONDS || 10)));
const SIGNUP_ENABLED = process.env.SIGNUP_ENABLED === "0" ? false : true;
const SESSION_DAYS = Math.max(1, Math.min(365, Number(process.env.SESSION_DAYS || 30)));

const SMTP_HOST = String(process.env.SMTP_HOST || "").trim();
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = String(process.env.SMTP_USER || "").trim();
const SMTP_PASS = String(process.env.SMTP_PASS || "");
const SMTP_SECURE = String(process.env.SMTP_SECURE || "").trim() === "1";
const MAIL_FROM = String(process.env.MAIL_FROM || SMTP_USER || "").trim();
const PUBLIC_BASE_URL = String(process.env.PUBLIC_BASE_URL || "").trim().replace(/\/+$/, "");
const ALLOWED_RETURN_ORIGINS = String(process.env.ALLOWED_RETURN_ORIGINS || "")
  .split(",")
  .map((s) => String(s || "").trim())
  .filter(Boolean);
const EMAIL_VERIFY = process.env.EMAIL_VERIFY === "0" ? false : true;
const EMAIL_VERIFY_TTL_MIN = (() => {
  const raw = Number(process.env.EMAIL_VERIFY_TTL_MIN || 24 * 60);
  if (!Number.isFinite(raw)) return 24 * 60;
  return Math.max(10, Math.min(7 * 24 * 60, Math.floor(raw)));
})();

const VIDEO_EXTS = new Set([".mp4", ".webm", ".mkv", ".avi", ".mov", ".m4v"]);

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(CACHE_DIR, { recursive: true });

const AUTH_SECRET = (() => {
  const env = String(process.env.AUTH_SECRET || "").trim();
  if (env) return Buffer.from(env);
  // Prefer a stable secret that isn't also a share token. If absent, fall back to legacy token.
  const secretFile = path.join(DATA_DIR, "auth-secret.txt");
  try {
    const s = fs.readFileSync(secretFile, "utf8").trim();
    if (s) return Buffer.from(s);
  } catch {
    // Ignore.
  }
  if (LEGACY_TOKEN) return Buffer.from(LEGACY_TOKEN);
  const fresh = crypto.randomBytes(32).toString("hex");
  try {
    fs.writeFileSync(secretFile, `${fresh}\n`, { mode: 0o600 });
  } catch {
    // Ignore.
  }
  return Buffer.from(fresh);
})();

const USERS_FILE = path.join(DATA_DIR, "users.json");
/**
 * @type {{
 *   users: Array<{
 *     id:string,
 *     username:string,
 *     email?:string,
 *     role:"admin"|"user",
 *     salt:string,
 *     passHash:string,
 *     quota:number,
 *     unlocked:string[],
 *     disabled?:boolean,
 *     accessUntilMs?:number|null,
 *     contentTokens?:Array<{id:string,name:string,maxUses:number,currentUses:number,createdAt:string,validUntil?:string,allowedVideos?:string[]}>,
 *     createdAt:string
 *   }>
 * }}
 */
let usersDb = { users: [] };
try {
  const raw = fs.readFileSync(USERS_FILE, "utf8");
  const parsed = JSON.parse(raw);
  if (parsed && Array.isArray(parsed.users)) usersDb = parsed;
} catch {
  // Ignore; file may not exist yet.
}

let saveChain = Promise.resolve();
function queueSaveUsers() {
  const body = Buffer.from(JSON.stringify(usersDb, null, 2));
  const tmp = `${USERS_FILE}.tmp`;
  saveChain = saveChain
    .then(async () => {
      await fsp.mkdir(DATA_DIR, { recursive: true });
      await fsp.writeFile(tmp, body, { mode: 0o600 });
      await fsp.rename(tmp, USERS_FILE);
    })
    .catch((err) => {
      console.error("Failed to save users:", err);
    });
  return saveChain;
}

const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");
/**
 * @type {{sessions: Array<{id:string,uid:string,deviceId?:string,deviceName?:string,userAgent?:string,ip?:string,createdAt:string,lastSeenAt?:string,revokedAt?:string}>}}
 */
let sessionsDb = { sessions: [] };
try {
  const raw = fs.readFileSync(SESSIONS_FILE, "utf8");
  const parsed = JSON.parse(raw);
  if (parsed && Array.isArray(parsed.sessions)) sessionsDb = parsed;
} catch {
  // Ignore; file may not exist yet.
}

let saveSessionsChain = Promise.resolve();
function queueSaveSessions() {
  const body = Buffer.from(JSON.stringify(sessionsDb, null, 2));
  const tmp = `${SESSIONS_FILE}.tmp`;
  saveSessionsChain = saveSessionsChain
    .then(async () => {
      await fsp.mkdir(DATA_DIR, { recursive: true });
      await fsp.writeFile(tmp, body, { mode: 0o600 });
      await fsp.rename(tmp, SESSIONS_FILE);
    })
    .catch((err) => {
      console.error("Failed to save sessions:", err);
    });
  return saveSessionsChain;
}

const CHAT_FILE = path.join(DATA_DIR, "chat.json");
/**
 * @type {{
 *   messages: Array<{
 *     id: string,
 *     ts: number,
 *     fromUid: string,
 *     fromUsername: string,
 *     fromRole: "admin"|"user",
 *     toUid: string|null,
 *     toRole: "admin"|"user",
 *     text: string
 *   }>
 * }}
 */
let chatDb = { messages: [] };
try {
  const raw = fs.readFileSync(CHAT_FILE, "utf8");
  const parsed = JSON.parse(raw);
  if (parsed && Array.isArray(parsed.messages)) chatDb = parsed;
} catch {
  // Ignore; file may not exist yet.
}

let saveChatChain = Promise.resolve();
function queueSaveChat() {
  const body = Buffer.from(JSON.stringify(chatDb, null, 2));
  const tmp = `${CHAT_FILE}.tmp`;
  saveChatChain = saveChatChain
    .then(async () => {
      await fsp.mkdir(DATA_DIR, { recursive: true });
      await fsp.writeFile(tmp, body, { mode: 0o600 });
      await fsp.rename(tmp, CHAT_FILE);
    })
    .catch((err) => {
      console.error("Failed to save chat:", err);
    });
  return saveChatChain;
}

const chatSendRateByUid = new Map(); // uid -> { windowStartMs:number, count:number }
function allowChatSend(uid) {
  const now = Date.now();
  const windowMs = 60_000;
  const limit = 20;
  let e = chatSendRateByUid.get(uid);
  if (!e || now - e.windowStartMs >= windowMs) {
    e = { windowStartMs: now, count: 0 };
  }
  e.count++;
  chatSendRateByUid.set(uid, e);
  return e.count <= limit;
}

function addChatMessage(msg) {
  if (!chatDb || !Array.isArray(chatDb.messages)) chatDb = { messages: [] };
  chatDb.messages.push(msg);
  const MAX = 5000;
  if (chatDb.messages.length > MAX) {
    chatDb.messages.splice(0, chatDb.messages.length - MAX);
  }
  queueSaveChat();
}

function json(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj, null, 2));
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    "Cache-Control": "no-store",
    // Anti-piracy headers
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Opener-Policy": "same-origin"
  });
  res.end(body);
}

function text(res, status, body, contentType = "text/plain; charset=utf-8") {
  const buf = Buffer.from(body);
  res.writeHead(status, {
    "Content-Type": contentType,
    "Content-Length": buf.length,
    "Cache-Control": "no-store",
    // Anti-piracy headers
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Opener-Policy": "same-origin"
  });
  res.end(buf);
}

function contentTypeForExt(ext) {
  switch (ext) {
    case ".mp4":
      return "video/mp4";
    case ".webm":
      return "video/webm";
    case ".mkv":
      return "video/x-matroska";
    case ".avi":
      return "video/x-msvideo";
    case ".mov":
      return "video/quicktime";
    case ".m4v":
      return "video/x-m4v";
    default:
      return "application/octet-stream";
  }
}

function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input));
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function b64urlToBuf(s) {
  const str = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = str.length % 4 ? "=".repeat(4 - (str.length % 4)) : "";
  return Buffer.from(str + pad, "base64");
}

function smtpConfigured() {
  return !!(nodemailer && SMTP_HOST && SMTP_USER && SMTP_PASS && MAIL_FROM);
}

function emailVerificationEnabled() {
  return EMAIL_VERIFY && smtpConfigured();
}

function isLocalHostName(hostname) {
  const h = String(hostname || "").trim().toLowerCase();
  if (!h) return true;
  if (h === "localhost" || h === "127.0.0.1" || h === "::1") return true;
  if (h.endsWith(".local")) return true;
  // If it's an IP literal, treat as local-ish for scheme guessing.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
  return false;
}

function guessPublicBaseUrl(req) {
  if (PUBLIC_BASE_URL) return PUBLIC_BASE_URL;

  const hostRaw = String(req.headers["x-forwarded-host"] || req.headers.host || "").split(",")[0].trim();
  if (!hostRaw) return "";
  const hostNoPort = hostRaw.includes(":") ? hostRaw.split(":")[0] : hostRaw;

  // Prefer explicit headers from proxies / Cloudflare Tunnel.
  let scheme = "";
  const xfproto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  if (xfproto === "http" || xfproto === "https") scheme = xfproto;
  if (!scheme) {
    const cfVisitor = String(req.headers["cf-visitor"] || "");
    const m = /\"scheme\":\"(https?)\"/i.exec(cfVisitor);
    if (m) scheme = String(m[1] || "").toLowerCase();
  }
  if (!scheme) scheme = isLocalHostName(hostNoPort) ? "http" : "https";

  return `${scheme}://${hostRaw}`;
}

function normalizeReturnTo(raw, fallbackBase) {
  const base = String(fallbackBase || "").replace(/\/+$/, "");
  if (!raw) return base ? `${base}/` : "/";
  const s = String(raw || "").trim();
  if (!s || s.length > 2000) return base ? `${base}/` : "/";
  let u;
  try {
    u = new URL(s);
  } catch {
    return base ? `${base}/` : "/";
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return base ? `${base}/` : "/";

  const allowed = new Set([u.origin, ...ALLOWED_RETURN_ORIGINS.map(String)]);
  // Always allow redirecting back to the same host the request came in on.
  if (base) {
    try {
      allowed.add(new URL(base).origin);
    } catch {
      // Ignore.
    }
  }
  if (!allowed.has(u.origin)) return base ? `${base}/` : "/";

  // Strip hash; we will add our own.
  return `${u.origin}${u.pathname}${u.search}`;
}

function getClientIp(req) {
  const cf = String(req.headers["cf-connecting-ip"] || "").trim();
  if (cf) return cf;
  const xff = String(req.headers["x-forwarded-for"] || "").trim();
  if (xff) return xff.split(",")[0].trim();
  return String(req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : "").trim();
}

const signupEmailRateByIp = new Map(); // ip -> {windowStartMs:number,count:number}
function allowSignupEmail(ip) {
  const key = String(ip || "unknown");
  const now = Date.now();
  const windowMs = 15 * 60_000;
  const limit = 3;
  let e = signupEmailRateByIp.get(key);
  if (!e || now - e.windowStartMs >= windowMs) e = { windowStartMs: now, count: 0 };
  e.count++;
  signupEmailRateByIp.set(key, e);
  return e.count <= limit;
}

let smtpTransporter = null;
function getSmtpTransporter() {
  if (!smtpConfigured()) return null;
  if (smtpTransporter) return smtpTransporter;
  const secure = SMTP_SECURE || SMTP_PORT === 465;
  smtpTransporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
  return smtpTransporter;
}

async function sendVerifyEmail({ toEmail, verifyUrl }) {
  const tr = getSmtpTransporter();
  if (!tr) throw new Error("smtp_not_configured");
  const subject = "Verify your email";
  const text = `Verify your email by opening this link:\n\n${verifyUrl}\n\nIf you did not request this, you can ignore this email.\n`;
  const html = `
    <div style="font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; line-height: 1.5;">
      <h2 style="margin: 0 0 12px;">Verify your email</h2>
      <p style="margin: 0 0 12px;">Click this link to verify your email and finish sign up:</p>
      <p style="margin: 0 0 16px;"><a href="${verifyUrl}">${verifyUrl}</a></p>
      <p style="margin: 0; color: #666;">If you did not request this, you can ignore this email.</p>
    </div>
  `;

  await tr.sendMail({
    from: MAIL_FROM,
    to: toEmail,
    subject,
    text,
    html,
  });
}

function makeAuthToken(user, sessionId = null) {
  const expMs = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  const payload = { uid: user.id, exp: expMs };
  if (sessionId) payload.sid = sessionId;
  const payloadB64 = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(payloadB64).digest();
  return `${payloadB64}.${b64url(sig)}`;
}

function makeContentToken(userId, tokenName, maxUses, validUntil, allowedVideos) {
  const expMs = validUntil ? new Date(validUntil).getTime() : Date.now() + 7 * 24 * 60 * 60 * 1000; // default 1 week
  const tokenId = crypto.randomUUID();
  const payload = { tid: tokenId, uid: userId, exp: expMs };
  const payloadB64 = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(payloadB64).digest();
  return {
    token: `${payloadB64}.${b64url(sig)}`,
    tokenId,
    name: tokenName,
    maxUses,
    validUntil: new Date(expMs).toISOString(),
    allowedVideos
  };
}

function makeContentTokenString(userId, tokenId, expMs) {
  const payload = { tid: tokenId, uid: userId, exp: expMs };
  const payloadB64 = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(payloadB64).digest();
  return `${payloadB64}.${b64url(sig)}`;
}

function makeEmailVerifyToken(userId, nonce, expMs, returnTo) {
  const payload = { typ: "ev", uid: userId, nonce: String(nonce || ""), exp: expMs, r: String(returnTo || "") };
  const payloadB64 = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(payloadB64).digest();
  return `${payloadB64}.${b64url(sig)}`;
}

function verifyEmailVerifyToken(token) {
  const t = String(token || "").trim();
  const dot = t.indexOf(".");
  if (dot < 0) return null;
  const payloadB64 = t.slice(0, dot);
  const sigB64 = t.slice(dot + 1);

  let payload;
  try {
    payload = JSON.parse(b64urlToBuf(payloadB64).toString("utf8"));
  } catch {
    return null;
  }
  if (!payload || payload.typ !== "ev") return null;
  if (typeof payload.uid !== "string" || typeof payload.exp !== "number" || typeof payload.nonce !== "string") return null;
  if (typeof payload.r !== "string") payload.r = "";
  if (Date.now() > payload.exp) return null;

  const expected = crypto.createHmac("sha256", AUTH_SECRET).update(payloadB64).digest();
  let got;
  try {
    got = b64urlToBuf(sigB64);
  } catch {
    return null;
  }
  if (got.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(got, expected)) return null;

  return { uid: payload.uid, nonce: payload.nonce, returnTo: payload.r };
}

function verifyAuthToken(token) {
  const t = String(token || "").trim();
  const dot = t.indexOf(".");
  if (dot < 0) return null;
  const payloadB64 = t.slice(0, dot);
  const sigB64 = t.slice(dot + 1);

  let payload;
  try {
    payload = JSON.parse(b64urlToBuf(payloadB64).toString("utf8"));
  } catch {
    return null;
  }
  if (!payload || typeof payload.uid !== "string" || typeof payload.exp !== "number") return null;
  if ("sid" in payload && payload.sid !== null && typeof payload.sid !== "string") return null;
  if (Date.now() > payload.exp) return null;

  const expected = crypto.createHmac("sha256", AUTH_SECRET).update(payloadB64).digest();
  let got;
  try {
    got = b64urlToBuf(sigB64);
  } catch {
    return null;
  }
  if (got.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(got, expected)) return null;

  const user = usersDb.users.find((u) => u.id === payload.uid);
  if (!user) return null;
  const disabled = !!user.disabled;
  const accessUntilMs = user.accessUntilMs === null ? null : typeof user.accessUntilMs === "number" ? user.accessUntilMs : null;
  const expired = typeof accessUntilMs === "number" ? Date.now() > accessUntilMs : false;

  let session = null;
  if (payload.sid) {
    session = sessionsDb.sessions.find((s) => s.id === payload.sid) || null;
    if (!session) return null;
    if (session.uid !== user.id) return null;
    if (session.revokedAt) return null;
  }

  return { user, session, sid: payload.sid || null, disabled, expired };
}

function verifyContentToken(token) {
  const t = String(token || "").trim();
  const dot = t.indexOf(".");
  if (dot < 0) return null;
  const payloadB64 = t.slice(0, dot);
  const sigB64 = t.slice(dot + 1);

  let payload;
  try {
    payload = JSON.parse(b64urlToBuf(payloadB64).toString("utf8"));
  } catch {
    return null;
  }
  if (!payload || typeof payload.tid !== "string" || typeof payload.uid !== "string" || typeof payload.exp !== "number") return null;
  if (Date.now() > payload.exp) return null;

  const expected = crypto.createHmac("sha256", AUTH_SECRET).update(payloadB64).digest();
  let got;
  try {
    got = b64urlToBuf(sigB64);
  } catch {
    return null;
  }
  if (got.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(got, expected)) return null;

  // Find user who owns this token
  const user = usersDb.users.find((u) => u.id === payload.uid);
  if (!user) return null;
  if (user.disabled) return null;
  if (typeof user.accessUntilMs === "number" && Date.now() > user.accessUntilMs) return null;
  
  // Find the specific token in the user's tokens
  const userToken = (user.contentTokens || []).find(t => t.id === payload.tid);
  if (!userToken) return null;
  
  return { user, tokenInfo: userToken };
}

function cleanUsername(raw) {
  const u = String(raw || "").trim();
  if (u.length < 3 || u.length > 32) return null;
  if (!/^[a-zA-Z0-9_.-]+$/.test(u)) return null;
  return u;
}

function normalizeEmail(raw) {
  const e = String(raw || "").trim().toLowerCase();
  if (!e) return null;
  if (e.length > 254) return null;
  if (/\s/.test(e)) return null;
  const at = e.indexOf("@");
  if (at <= 0 || at === e.length - 1) return null;
  const local = e.slice(0, at);
  const domain = e.slice(at + 1);
  if (local.length > 64) return null;
  if (domain.length < 3) return null;
  if (!domain.includes(".")) return null;
  if (!/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)) return null;
  if (!/^[a-z0-9.-]+$/.test(domain)) return null;
  if (domain.startsWith(".") || domain.endsWith(".")) return null;
  if (domain.includes("..")) return null;
  return e;
}

function isEmailLike(raw) {
  return String(raw || "").includes("@");
}

function deriveUsernameFromEmail(email) {
  const e = normalizeEmail(email);
  if (!e) return null;
  const local = e.split("@")[0];
  // Convert to allowed username chars.
  let base = local
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "")
    .replace(/^[_.-]+/, "")
    .replace(/[_.-]+$/, "");

  if (base.length < 3) base = "user";
  if (base.length > 32) base = base.slice(0, 32);
  base = cleanUsername(base) || "user";
  return base;
}

function normalizePassword(raw) {
  const p = String(raw || "");
  if (p.length < 8 || p.length > 256) return null;
  return p;
}

function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) return reject(err);
      resolve(key);
    });
  });
}

async function verifyPassword(user, password) {
  const derived = await scryptAsync(password, Buffer.from(user.salt, "hex"));
  const expected = Buffer.from(user.passHash, "hex");
  if (expected.length !== derived.length) return false;
  return crypto.timingSafeEqual(expected, derived);
}

async function readJson(req, limitBytes = 1_000_000) {
  const chunks = [];
  let total = 0;
  return new Promise((resolve, reject) => {
    req.on("data", (d) => {
      total += d.length;
      if (total > limitBytes) {
        reject(new Error("Payload too large"));
        req.destroy();
        return;
      }
      chunks.push(d);
    });
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : null);
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function safeDecodeSegments(urlPathAfterPrefix) {
  const parts = urlPathAfterPrefix.split("/").filter(Boolean);
  const decoded = parts.map((p) => {
    const d = decodeURIComponent(p);
    if (!d || d === "." || d === ".." || d.includes("/") || d.includes("\\")) {
      throw new Error("Invalid path segment");
    }
    return d;
  });
  return decoded;
}

function insideBase(baseDir, absPath) {
  const rel = path.relative(baseDir, absPath);
  return rel && !rel.startsWith("..") && !path.isAbsolute(rel);
}

function safeRelPathFromClient(relPath) {
  const raw = String(relPath || "");
  const parts = raw.split("/").filter(Boolean);
  if (parts.length === 0) throw new Error("Empty path");
  for (const p of parts) {
    if (!p || p === "." || p === ".." || p.includes("\\") || p.includes("\0")) throw new Error("Invalid path");
  }
  return parts.join("/");
}

async function listVideosRecursive(baseDir) {
  /** @type {{path:string,name:string,ext:string,size:number,mtimeMs:number}[]} */
  const out = [];

  async function walk(absDir, relPrefix) {
    let entries;
    try {
      entries = await fsp.readdir(absDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const ent of entries) {
      if (ent.isDirectory()) {
        await walk(path.join(absDir, ent.name), `${relPrefix}${ent.name}/`);
        continue;
      }
      if (!ent.isFile()) continue;

      const ext = path.extname(ent.name).toLowerCase();
      if (!VIDEO_EXTS.has(ext)) continue;

      const absFile = path.join(absDir, ent.name);
      let st;
      try {
        st = await fsp.stat(absFile);
      } catch {
        continue;
      }

      out.push({
        path: `${relPrefix}${ent.name}`,
        name: ent.name,
        ext: ext.slice(1),
        size: st.size,
        mtimeMs: st.mtimeMs,
      });
    }
  }

  await walk(baseDir, "");
  out.sort((a, b) => a.path.localeCompare(b.path));
  return out;
}

async function serveIndex(req, res) {
  try {
    const buf = await fsp.readFile(INDEX_FILE);
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Length": buf.length,
      "Cache-Control": "no-store",
    });
    if (req.method === "HEAD") return res.end();
    res.end(buf);
  } catch (err) {
    text(res, 500, `Missing index.html at ${INDEX_FILE}\n`);
  }
}

async function serveFile(req, res, abs, { contentType, downloadName } = {}) {
  let st;
  try {
    st = await fsp.stat(abs);
  } catch {
    return text(res, 404, "Not found\n");
  }
  if (!st.isFile()) return text(res, 404, "Not found\n");

  const ext = path.extname(abs).toLowerCase();
  const ct = contentType || contentTypeForExt(ext);
  const size = st.size;

  res.setHeader("Accept-Ranges", "bytes");
  res.setHeader("Content-Type", ct);
  res.setHeader("Cache-Control", "no-store");
  if (downloadName) {
    res.setHeader("Content-Disposition", `attachment; filename="${String(downloadName).replace(/\"/g, "")}"`);
  }

  const range = req.headers.range;
  if (!range) {
    res.statusCode = 200;
    res.setHeader("Content-Length", size);
    if (req.method === "HEAD") return res.end();
    fs.createReadStream(abs).pipe(res);
    return;
  }

  const m = /^bytes=(\d+)-(\d*)$/.exec(range);
  if (!m) {
    res.statusCode = 416;
    res.setHeader("Content-Range", `bytes */${size}`);
    return res.end();
  }

  const start = Number(m[1]);
  const end = m[2] ? Number(m[2]) : size - 1;
  if (Number.isNaN(start) || Number.isNaN(end) || start > end || start >= size) {
    res.statusCode = 416;
    res.setHeader("Content-Range", `bytes */${size}`);
    return res.end();
  }

  const chunkSize = end - start + 1;
  res.statusCode = 206;
  res.setHeader("Content-Range", `bytes ${start}-${end}/${size}`);
  res.setHeader("Content-Length", chunkSize);
  if (req.method === "HEAD") return res.end();
  fs.createReadStream(abs, { start, end }).pipe(res);
}

async function resolveVideoFromUrlPath(relUrlPath) {
  let segments;
  try {
    segments = safeDecodeSegments(relUrlPath);
  } catch {
    throw new Error("Bad media path");
  }
  const relFsPath = path.join(...segments);
  const abs = path.resolve(VIDEO_DIR, relFsPath);
  if (!insideBase(VIDEO_DIR, abs)) throw new Error("Forbidden");
  const ext = path.extname(abs).toLowerCase();
  if (!VIDEO_EXTS.has(ext)) throw new Error("Unsupported");
  return { abs, relDecoded: segments.join("/") };
}

function cacheKeyForVideo(relPath, st) {
  const h = crypto.createHash("sha256").update(String(relPath)).digest("hex").slice(0, 32);
  return `${h}_${st.size}_${Math.floor(st.mtimeMs)}`;
}

async function fileExists(p) {
  try {
    await fsp.access(p, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function runFfmpeg(args) {
  await new Promise((resolve, reject) => {
    const child = spawn("ffmpeg", args, { stdio: ["ignore", "ignore", "pipe"] });
    let errBuf = "";
    child.stderr.on("data", (d) => {
      errBuf += d.toString("utf8");
      if (errBuf.length > 8_000) errBuf = errBuf.slice(-8_000);
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) return resolve();
      reject(new Error(errBuf.trim() || `ffmpeg failed (code ${code})`));
    });
  });
}

async function runFfprobeDurationSec(absVideo) {
  return await new Promise((resolve) => {
    const child = spawn(
      "ffprobe",
      [
        "-hide_banner",
        "-v",
        "error",
        "-show_entries",
        "format=duration",
        "-of",
        "default=noprint_wrappers=1:nokey=1",
        absVideo,
      ],
      { stdio: ["ignore", "pipe", "pipe"] }
    );
    let outBuf = "";
    let errBuf = "";
    child.stdout.on("data", (d) => {
      outBuf += d.toString("utf8");
      if (outBuf.length > 4_000) outBuf = outBuf.slice(-4_000);
    });
    child.stderr.on("data", (d) => {
      errBuf += d.toString("utf8");
      if (errBuf.length > 8_000) errBuf = errBuf.slice(-8_000);
    });
    child.on("error", () => resolve(null));
    child.on("close", (code) => {
      if (code !== 0) return resolve(null);
      const s = String(outBuf || "").trim();
      const n = Number.parseFloat(s);
      if (!Number.isFinite(n) || n < 0) return resolve(null);
      resolve(n);
    });
  });
}

const durationMetaInFlight = new Map(); // metaPath -> Promise<number|null>
async function loadDurationMeta(metaPath) {
  try {
    const raw = await fsp.readFile(metaPath, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || !Object.prototype.hasOwnProperty.call(parsed, "durationSec")) return { hit: false, durationSec: null };
    const v = parsed.durationSec;
    if (typeof v === "number" && Number.isFinite(v) && v >= 0) return { hit: true, durationSec: v };
    return { hit: true, durationSec: null };
  } catch {
    return { hit: false, durationSec: null };
  }
}

async function writeDurationMeta(metaPath, durationSec) {
  const rec = {
    durationSec: typeof durationSec === "number" && Number.isFinite(durationSec) && durationSec >= 0 ? durationSec : null,
    computedAt: new Date().toISOString(),
  };
  const tmp = `${metaPath}.tmp`;
  try {
    await fsp.writeFile(tmp, JSON.stringify(rec, null, 2) + "\n", { mode: 0o600 });
    await fsp.rename(tmp, metaPath);
  } catch {
    try {
      await fsp.unlink(tmp);
    } catch {
      // Ignore.
    }
  }
}

async function ensureDurationMeta(absVideo, relPath, st) {
  const key = cacheKeyForVideo(relPath, st);
  const metaPath = path.join(CACHE_DIR, `${key}.meta.json`);
  const cached = await loadDurationMeta(metaPath);
  if (cached.hit) return { key, durationSec: cached.durationSec };

  let p = durationMetaInFlight.get(metaPath) || null;
  if (!p) {
    p = (async () => {
      const dur = await runFfprobeDurationSec(absVideo);
      await writeDurationMeta(metaPath, dur);
      return dur;
    })()
      .catch(() => {
        // Best-effort cache a null so we don't retry forever.
        writeDurationMeta(metaPath, null).catch(() => {});
        return null;
      })
      .finally(() => {
        durationMetaInFlight.delete(metaPath);
      });
    durationMetaInFlight.set(metaPath, p);
  }
  const durationSec = await p;
  return { key, durationSec };
}

async function ensureThumb(absVideo, relPath) {
  const st = await fsp.stat(absVideo);
  const key = cacheKeyForVideo(relPath, st);
  const out = path.join(CACHE_DIR, `${key}.jpg`);
  if (await fileExists(out)) return out;
  const tmp = `${out}.tmp.jpg`;
  await runFfmpeg([
    "-hide_banner",
    "-loglevel",
    "error",
    "-i",
    absVideo,
    "-vf",
    "thumbnail,scale=360:-2",
    "-frames:v",
    "1",
    "-q:v",
    "5",
    tmp,
  ]);
  await fsp.rename(tmp, out);
  return out;
}

async function ensurePreview(absVideo, relPath) {
  const st = await fsp.stat(absVideo);
  const key = cacheKeyForVideo(relPath, st);
  const out = path.join(CACHE_DIR, `${key}_p${PREVIEW_SECONDS}.mp4`);
  if (await fileExists(out)) return out;
  const tmp = `${out}.tmp.mp4`;
  await runFfmpeg([
    "-hide_banner",
    "-loglevel",
    "error",
    "-i",
    absVideo,
    "-t",
    String(PREVIEW_SECONDS),
    "-an",
    "-vf",
    "scale='min(1280,iw)':-2",
    "-c:v",
    "libx264",
    "-preset",
    "veryfast",
    "-crf",
    "30",
    "-movflags",
    "+faststart",
    tmp,
  ]);
  await fsp.rename(tmp, out);
  return out;
}

function localUrls(port) {
  const out = new Set();
  out.add(`http://127.0.0.1:${port}/`);
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const ni of nets[name] || []) {
      if (!ni || ni.internal) continue;
      if (ni.family !== "IPv4") continue;
      out.add(`http://${ni.address}:${port}/`);
    }
  }
  return [...out].sort();
}

function authContext(req, url) {
  if (LEGACY_TOKEN && url.searchParams.get("token") === LEGACY_TOKEN) {
    return { kind: "legacy", role: "admin" };
  }

  const header = String(req.headers.authorization || "");
  const bearer = header.toLowerCase().startsWith("bearer ") ? header.slice(7).trim() : "";
  const q = String(url.searchParams.get("auth") || "").trim();
  const tok = bearer || q;
  if (!tok) {
    // Check for content token
    const contentToken = String(url.searchParams.get("contentToken") || "").trim();
    if (contentToken) {
      return verifyContentToken(contentToken);
    }
    return null;
  }

  const v = verifyAuthToken(tok);
  if (!v) return null;
  return {
    kind: "user",
    role: v.user.role,
    user: v.user,
    session: v.session,
    sid: v.sid,
    disabled: v.disabled,
    expired: v.expired,
  };
}

function authInactiveReason(ctx) {
  if (!ctx || ctx.kind !== "user") return null;
  if (ctx.disabled) return "disabled";
  if (ctx.expired) return "expired";
  return null;
}

function getClientIp(req) {
  const cf = String(req.headers["cf-connecting-ip"] || "").trim();
  if (cf) return cf;
  const xff = String(req.headers["x-forwarded-for"] || "").trim();
  if (xff) return xff.split(",")[0].trim();
  return String((req.socket && req.socket.remoteAddress) || "").trim();
}

function sanitizeDeviceField(raw, maxLen = 160) {
  const s = String(raw || "").trim();
  if (!s) return "";
  return s.length > maxLen ? s.slice(0, maxLen) : s;
}

function createSessionForUser(user, { deviceId, deviceName, req }) {
  const now = new Date().toISOString();
  const session = {
    id: crypto.randomUUID(),
    uid: user.id,
    deviceId: sanitizeDeviceField(deviceId, 120) || undefined,
    deviceName: sanitizeDeviceField(deviceName, 120) || undefined,
    userAgent: sanitizeDeviceField(req.headers["user-agent"], 260) || undefined,
    ip: sanitizeDeviceField(getClientIp(req), 80) || undefined,
    createdAt: now,
    lastSeenAt: now,
  };
  sessionsDb.sessions.push(session);
  return session;
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const { pathname } = url;

    // Basic CORS for API/media if someone hosts index.html elsewhere.
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST");
    res.setHeader("Access-Control-Allow-Headers", "Range,Content-Type,Authorization");
    if (req.method === "OPTIONS") return res.end();

    // Serve the single-page UI on known routes.
    if (pathname === "/" || pathname === "/index.html" || pathname === "/admin" || pathname.startsWith("/admin/")) {
      return serveIndex(req, res);
    }

	    if (pathname === "/api/info") {
	      return json(res, 200, {
	        ok: true,
	        mode: "server",
	        videoDirName: path.basename(VIDEO_DIR),
	        videoDir: VIDEO_DIR,
	        exts: [...VIDEO_EXTS].map((e) => e.slice(1)),
	        auth: {
	          legacyToken: LEGACY_TOKEN ? true : false,
	          users: true,
	          signupEnabled: SIGNUP_ENABLED,
	          emailVerification: emailVerificationEnabled(),
	          previewSeconds: PREVIEW_SECONDS,
	        },
	        now: new Date().toISOString(),
	      });
	    }

	    if (pathname === "/api/auth/signup" && req.method === "POST") {
	      if (!SIGNUP_ENABLED) return json(res, 403, { ok: false, error: "signup_disabled" });
	      const body = await readJson(req).catch(() => null);
	      const password = normalizePassword(body && body.password);
	      if (!password) return json(res, 400, { ok: false, error: "bad_request" });

	      const rawEmail = body && Object.prototype.hasOwnProperty.call(body, "email") ? body.email : null;
	      const email = normalizeEmail(rawEmail);
	      if (!email) return json(res, 400, { ok: false, error: "bad_email" });

	      const base = guessPublicBaseUrl(req);
	      const returnTo = normalizeReturnTo(body && (body.return_to ?? body.returnTo ?? body.returnToUrl), base);

	      // Email verification flow (recommended). If SMTP isn't configured (or EMAIL_VERIFY=0), fall back to the
	      // old immediate sign-up behavior for local/dev usage.
	      if (emailVerificationEnabled()) {
	        const ip = getClientIp(req);
	        if (!allowSignupEmail(ip)) return json(res, 429, { ok: false, error: "rate_limited" });

	        let user = usersDb.users.find((u) => String(u.email || "").toLowerCase() === email) || null;
	        const nowIso = new Date().toISOString();
	        const expMs = Date.now() + EMAIL_VERIFY_TTL_MIN * 60_000;

	        if (user) {
	          const verified = user.emailVerified === false ? false : true;
	          if (verified) return json(res, 409, { ok: false, error: "email_taken" });

	          // Update password + rotate verification nonce.
	          const salt = crypto.randomBytes(16);
	          const derived = await scryptAsync(password, salt);
	          user.salt = salt.toString("hex");
	          user.passHash = derived.toString("hex");
	          user.verifyNonce = crypto.randomBytes(16).toString("hex");
	          user.verifyExpiresAt = expMs;
	          user.needsUsername = true;
	          if (!user.createdAt) user.createdAt = nowIso;
	          await queueSaveUsers();
	        } else {
	          /** @type {"admin" | "user"} */
	          const role = usersDb.users.length === 0 ? "admin" : "user";
	          const salt = crypto.randomBytes(16);
	          const derived = await scryptAsync(password, salt);
	          user = {
	            id: crypto.randomUUID(),
	            username: `u_${crypto.randomBytes(4).toString("hex")}`,
	            email,
	            role,
	            salt: salt.toString("hex"),
	            passHash: derived.toString("hex"),
	            quota: role === "admin" ? -1 : 0,
	            unlocked: [],
	            contentTokens: [],
	            disabled: false,
	            accessUntilMs: null,
	            emailVerified: false,
	            verifyNonce: crypto.randomBytes(16).toString("hex"),
	            verifyExpiresAt: expMs,
	            needsUsername: true,
	            createdAt: nowIso,
	          };
	          usersDb.users.push(user);
	          await queueSaveUsers();
	        }

	        if (!base) return json(res, 500, { ok: false, error: "missing_public_base" });
	        const token = makeEmailVerifyToken(user.id, String(user.verifyNonce || ""), expMs, returnTo);
	        const verifyUrl = `${base}/api/auth/verify-email?token=${encodeURIComponent(token)}`;
	        try {
	          await sendVerifyEmail({ toEmail: email, verifyUrl });
	        } catch (err) {
	          console.error("Failed to send verification email:", err);
	          return json(res, 500, { ok: false, error: "email_send_failed" });
	        }
	        return json(res, 200, { ok: true, pending: true });
	      }

	      // Legacy immediate signup (no email verification).
	      // Derive a username from the email and ensure uniqueness.
	      let username = deriveUsernameFromEmail(email);
	      if (!username) return json(res, 400, { ok: false, error: "bad_request" });
	      if (usersDb.users.some((u) => String(u.email || "").toLowerCase() === email)) {
	        return json(res, 409, { ok: false, error: "email_taken" });
	      }
	      if (usersDb.users.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
	        const baseName = username;
	        for (let i = 1; i <= 999; i++) {
	          const suffix = `_${i}`;
	          const trimmed = baseName.length + suffix.length > 32 ? baseName.slice(0, 32 - suffix.length) : baseName;
	          const cand = `${trimmed}${suffix}`;
	          if (!usersDb.users.some((u) => u.username.toLowerCase() === cand.toLowerCase())) {
	            username = cand;
	            break;
	          }
	        }
	        if (usersDb.users.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
	          return json(res, 409, { ok: false, error: "username_taken" });
	        }
	      }

	      const salt = crypto.randomBytes(16);
	      const derived = await scryptAsync(password, salt);
	      /** @type {"admin" | "user"} */
	      const role = usersDb.users.length === 0 ? "admin" : "user";
	      const user = {
	        id: crypto.randomUUID(),
	        username,
	        email,
	        role,
	        salt: salt.toString("hex"),
	        passHash: derived.toString("hex"),
	        quota: role === "admin" ? -1 : 0,
	        unlocked: [],
	        contentTokens: [],
	        disabled: false,
	        accessUntilMs: null,
	        emailVerified: true,
	        needsUsername: false,
	        createdAt: new Date().toISOString(),
	      };
	      usersDb.users.push(user);
	      await queueSaveUsers();

	      const session = createSessionForUser(user, { deviceId: body && body.deviceId, deviceName: body && body.deviceName, req });
	      await queueSaveSessions();
	      const auth = makeAuthToken(user, session.id);
	      return json(res, 200, { ok: true, user: { username: user.username, email: user.email || "", role: user.role, quota: user.quota }, auth });
	    }

	    if (pathname === "/api/auth/verify-email" && req.method === "GET") {
	      const base = guessPublicBaseUrl(req);
	      const tokenRaw = url.searchParams.get("token") || "";
	      const v = verifyEmailVerifyToken(tokenRaw);
	      const returnTo = normalizeReturnTo(v && v.returnTo ? v.returnTo : "", base);

	      const redirectWith = (hash) => {
	        const loc = `${returnTo}#${hash}`;
	        res.writeHead(302, { Location: loc, "Cache-Control": "no-store" });
	        res.end();
	      };

	      if (!v) return redirectWith("error=invalid_or_expired_link");

	      const user = usersDb.users.find((u) => u.id === v.uid) || null;
	      if (!user) return redirectWith("error=invalid_or_expired_link");
	      if (user.disabled) return redirectWith("error=account_disabled");
	      if (typeof user.accessUntilMs === "number" && Date.now() > user.accessUntilMs) return redirectWith("error=access_expired");

	      const alreadyVerified = user.emailVerified === false ? false : true;
	      if (!alreadyVerified) {
	        const nonce = String(user.verifyNonce || "");
	        const expMs = typeof user.verifyExpiresAt === "number" ? user.verifyExpiresAt : 0;
	        if (!nonce || nonce !== v.nonce) return redirectWith("error=invalid_or_expired_link");
	        if (expMs && Date.now() > expMs) return redirectWith("error=invalid_or_expired_link");

	        user.emailVerified = true;
	        user.verifyNonce = "";
	        user.verifyExpiresAt = null;
	        if (user.needsUsername !== false) user.needsUsername = true;
	        await queueSaveUsers();
	      }

	      const session = createSessionForUser(user, { deviceId: "", deviceName: "", req });
	      await queueSaveSessions();
	      const auth = makeAuthToken(user, session.id);
	      const setup = user.needsUsername ? "&setup=1" : "";
	      return redirectWith(`auth=${encodeURIComponent(auth)}${setup}`);
	    }

	    if (pathname === "/api/auth/login" && req.method === "POST") {
	      const body = await readJson(req).catch(() => null);
	      const password = normalizePassword(body && body.password);
	      const identifierRaw = String((body && (body.identifier ?? body.email ?? body.username)) || "").trim();
	      if (!identifierRaw || !password) return json(res, 400, { ok: false, error: "bad_request" });

      /** @type {any} */
      let user = null;
      if (isEmailLike(identifierRaw)) {
        const email = normalizeEmail(identifierRaw);
        if (!email) return json(res, 400, { ok: false, error: "bad_request" });
        user = usersDb.users.find((u) => String(u.email || "").toLowerCase() === email) || null;
      } else {
        const username = cleanUsername(identifierRaw);
        if (!username) return json(res, 400, { ok: false, error: "bad_request" });
        user = usersDb.users.find((u) => u.username.toLowerCase() === username.toLowerCase()) || null;
      }
	      if (!user) return json(res, 401, { ok: false, error: "invalid_credentials" });
	      const ok = await verifyPassword(user, password).catch(() => false);
	      if (!ok) return json(res, 401, { ok: false, error: "invalid_credentials" });

	      if (user.email && user.emailVerified === false) return json(res, 403, { ok: false, error: "email_not_verified" });
	      if (user.disabled) return json(res, 403, { ok: false, error: "account_disabled" });
	      if (typeof user.accessUntilMs === "number" && Date.now() > user.accessUntilMs) return json(res, 403, { ok: false, error: "access_expired" });

	      const session = createSessionForUser(user, { deviceId: body && body.deviceId, deviceName: body && body.deviceName, req });
	      await queueSaveSessions();
      const auth = makeAuthToken(user, session.id);
      return json(res, 200, { ok: true, user: { username: user.username, email: user.email || "", role: user.role, quota: user.quota }, auth });
    }

    if (pathname === "/api/me") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      if (ctx.kind === "legacy") return json(res, 200, { ok: true, user: { username: "legacy-token", role: "admin", quota: -1, unlockedCount: -1 } });
      if (ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
	      const u = ctx.user;
	      const accessUntilMs = u.accessUntilMs === null ? null : typeof u.accessUntilMs === "number" ? u.accessUntilMs : null;
	      const accessRemainingMs = typeof accessUntilMs === "number" ? Math.max(0, accessUntilMs - Date.now()) : null;
	      const emailVerified = u.email ? (u.emailVerified === false ? false : true) : true;
	      return json(res, 200, {
	        ok: true,
	        inactive: authInactiveReason(ctx),
	        user: {
	          username: u.username,
	          email: u.email || "",
	          role: u.role,
	          quota: u.quota,
	          unlockedCount: Array.isArray(u.unlocked) ? u.unlocked.length : 0,
	          disabled: !!u.disabled,
	          emailVerified,
	          needsUsername: !!u.needsUsername,
	          accessUntilMs,
	          accessRemainingMs,
	          contentTokens: u.contentTokens || [],
	        },
	      });
	    }

	    if (pathname === "/api/me/username" && req.method === "POST") {
	      const ctx = authContext(req, url);
	      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
	      const inactive = authInactiveReason(ctx);
	      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
	      if (ctx.kind !== "user") return json(res, 403, { ok: false, error: "forbidden" });

	      const body = await readJson(req).catch(() => null);
	      const username = cleanUsername(body && body.username);
	      if (!username) return json(res, 400, { ok: false, error: "bad_username" });

	      const taken = usersDb.users.some((u) => u.id !== ctx.user.id && String(u.username || "").toLowerCase() === username.toLowerCase());
	      if (taken) return json(res, 409, { ok: false, error: "username_taken" });

	      ctx.user.username = username;
	      ctx.user.needsUsername = false;
	      await queueSaveUsers();
	      return json(res, 200, {
	        ok: true,
	        user: {
	          username: ctx.user.username,
	          email: ctx.user.email || "",
	          role: ctx.user.role,
	          quota: ctx.user.quota,
	          unlockedCount: Array.isArray(ctx.user.unlocked) ? ctx.user.unlocked.length : 0,
	          emailVerified: ctx.user.email ? (ctx.user.emailVerified === false ? false : true) : true,
	          needsUsername: !!ctx.user.needsUsername,
	        },
	      });
	    }

    if (pathname === "/api/ping" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx || ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });

      const body = await readJson(req).catch(() => null);
      let session = ctx.session;
      let refreshedAuth = "";
      if (!session) {
        session = createSessionForUser(ctx.user, { deviceId: body && body.deviceId, deviceName: body && body.deviceName, req });
        await queueSaveSessions();
        refreshedAuth = makeAuthToken(ctx.user, session.id);
      } else {
        const did = sanitizeDeviceField(body && body.deviceId, 120);
        const dname = sanitizeDeviceField(body && body.deviceName, 120);
        if (did) session.deviceId = did;
        if (dname) session.deviceName = dname;
        session.userAgent = sanitizeDeviceField(req.headers["user-agent"], 260) || session.userAgent;
        session.ip = sanitizeDeviceField(getClientIp(req), 80) || session.ip;
        session.lastSeenAt = new Date().toISOString();
        await queueSaveSessions();
      }

      const u = ctx.user;
      const accessUntilMs = u.accessUntilMs === null ? null : typeof u.accessUntilMs === "number" ? u.accessUntilMs : null;
      const accessRemainingMs = typeof accessUntilMs === "number" ? Math.max(0, accessUntilMs - Date.now()) : null;
      return json(res, 200, {
        ok: true,
        auth: refreshedAuth || undefined,
        user: {
          username: u.username,
          email: u.email || "",
          role: u.role,
          quota: u.quota,
          unlockedCount: Array.isArray(u.unlocked) ? u.unlocked.length : 0,
          disabled: !!u.disabled,
          accessUntilMs,
          accessRemainingMs,
        },
        session: session ? { id: session.id, deviceId: session.deviceId || "", deviceName: session.deviceName || "" } : null,
      });
    }

    if (pathname === "/api/chat/history") {
      const ctx = authContext(req, url);
      if (!ctx || ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });

      const limitRaw = Number(url.searchParams.get("limit") || 60);
      const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(200, Math.floor(limitRaw))) : 60;
      const uid = ctx.user.id;
      const all = Array.isArray(chatDb.messages) ? chatDb.messages : [];
      const filtered = all.filter((m) => m && (m.fromUid === uid || m.toUid === uid)).sort((a, b) => (a.ts || 0) - (b.ts || 0));
      const messages = filtered
        .slice(-limit)
        .map((m) => ({ id: m.id, ts: m.ts, fromRole: m.fromRole, fromUsername: m.fromUsername, text: m.text }));
      return json(res, 200, { ok: true, messages, now: Date.now() });
    }

    if (pathname === "/api/chat/updates") {
      const ctx = authContext(req, url);
      if (!ctx || ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });

      const sinceRaw = Number(url.searchParams.get("since") || 0);
      const since = Number.isFinite(sinceRaw) ? Math.max(0, Math.floor(sinceRaw)) : 0;
      const uid = ctx.user.id;
      const all = Array.isArray(chatDb.messages) ? chatDb.messages : [];
      const messages = all
        .filter((m) => m && (m.fromUid === uid || m.toUid === uid) && typeof m.ts === "number" && m.ts > since)
        .sort((a, b) => (a.ts || 0) - (b.ts || 0))
        .slice(0, 200)
        .map((m) => ({ id: m.id, ts: m.ts, fromRole: m.fromRole, fromUsername: m.fromUsername, text: m.text }));
      return json(res, 200, { ok: true, messages, now: Date.now() });
    }

    if (pathname === "/api/chat/send" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx || ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (String(ctx.user.role || "") === "admin") return json(res, 403, { ok: false, error: "forbidden" });

      const body = await readJson(req).catch(() => null);
      const textRaw = String(body && body.text ? body.text : "").trim();
      if (!textRaw) return json(res, 400, { ok: false, error: "bad_request" });
      if (textRaw.length > 2000) return json(res, 400, { ok: false, error: "too_long" });
      if (!allowChatSend(ctx.user.id)) return json(res, 429, { ok: false, error: "rate_limited" });

      addChatMessage({
        id: crypto.randomUUID(),
        ts: Date.now(),
        fromUid: ctx.user.id,
        fromUsername: ctx.user.username,
        fromRole: ctx.user.role,
        toUid: null,
        toRole: "admin",
        text: textRaw,
      });
      return json(res, 200, { ok: true });
    }

    if (pathname === "/api/videos") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      
      const inactive = authInactiveReason(ctx);
      if (inactive) {
        const u = ctx.user;
        return json(res, 403, {
          ok: false,
          error: inactive === "disabled" ? "account_disabled" : "access_expired",
          accessUntilMs: typeof u.accessUntilMs === "number" ? u.accessUntilMs : null,
        });
      }

      const videos = await listVideosRecursive(VIDEO_DIR);
      
      // Content token access (no login): filter to allowed videos and mark unlocked based on remaining uses.
      if (ctx.tokenInfo) {
        const token = ctx.tokenInfo;
        const allowed = Array.isArray(token.allowedVideos) ? token.allowedVideos.map(String) : [];
        const allowedSet = allowed.length ? new Set(allowed) : null;

        const used = Array.isArray(token.usedVideos) ? token.usedVideos.map(String) : [];
        const usedSet = new Set(used);

        const maxUses = Number(token.maxUses);
        const unlimited = Number.isFinite(maxUses) && maxUses < 0;
        const canUnlockNew = unlimited || (Number.isFinite(maxUses) && maxUses > 0 && usedSet.size < maxUses);

        const list = videos
          .filter((v) => !allowedSet || allowedSet.has(v.path))
          .map((v) => ({ ...v, unlocked: usedSet.has(v.path) || canUnlockNew }));

	        return json(res, 200, {
	          ok: true,
	          count: list.length,
	          videos: list,
	          user: {
	            role: "token-user",
	            quota: unlimited ? -1 : Number.isFinite(maxUses) ? Math.floor(maxUses) : 0,
	            unlockedCount: usedSet.size,
	            emailVerified: true,
	            needsUsername: false,
	          },
	        });
	      }
	      
	      if (ctx.kind === "legacy" || ctx.role === "admin") {
	        const list = videos.map((v) => ({ ...v, unlocked: true }));
	        return json(res, 200, {
	          ok: true,
	          count: list.length,
	          videos: list,
	          user: { role: "admin", quota: -1, unlockedCount: -1, emailVerified: true, needsUsername: false },
	        });
	      }
	      const unlockedSet = new Set((ctx.user.unlocked || []).map(String));
	      const list = videos.map((v) => ({ ...v, unlocked: unlockedSet.has(v.path) }));
	      return json(res, 200, {
	        ok: true,
        count: list.length,
        videos: list,
	        user: {
	          username: ctx.user.username,
	          email: ctx.user.email || "",
	          role: ctx.user.role,
	          quota: ctx.user.quota,
	          unlockedCount: unlockedSet.size,
	          emailVerified: ctx.user.email ? (ctx.user.emailVerified === false ? false : true) : true,
	          needsUsername: !!ctx.user.needsUsername,
	        },
	      });
	    }

    if (pathname === "/api/video-meta" && req.method === "GET") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });

      let relPath;
      try {
        relPath = safeRelPathFromClient(url.searchParams.get("path"));
      } catch {
        return json(res, 400, { ok: false, error: "bad_path" });
      }

      const abs = path.resolve(VIDEO_DIR, relPath);
      if (!insideBase(VIDEO_DIR, abs)) return json(res, 403, { ok: false, error: "forbidden" });
      const ext = path.extname(abs).toLowerCase();
      if (!VIDEO_EXTS.has(ext)) return json(res, 400, { ok: false, error: "unsupported" });

      let st;
      try {
        st = await fsp.stat(abs);
        if (!st.isFile()) return json(res, 404, { ok: false, error: "not_found" });
      } catch {
        return json(res, 404, { ok: false, error: "not_found" });
      }

      // Content token access (no login): restrict meta to allowed videos if configured.
      if (ctx.tokenInfo) {
        const allowed = Array.isArray(ctx.tokenInfo.allowedVideos) ? ctx.tokenInfo.allowedVideos.map(String) : [];
        if (allowed.length && !allowed.includes(relPath)) return json(res, 403, { ok: false, error: "forbidden" });
      }

      const meta = await ensureDurationMeta(abs, relPath, st);
      const durationSec = typeof meta.durationSec === "number" && Number.isFinite(meta.durationSec) ? meta.durationSec : null;
      return json(res, 200, { ok: true, path: relPath, durationSec });
    }

    if (pathname === "/api/unlock" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx || ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      const body = await readJson(req).catch(() => null);
      let relPath;
      try {
        relPath = safeRelPathFromClient(body && body.path);
      } catch {
        return json(res, 400, { ok: false, error: "bad_path" });
      }

      const abs = path.resolve(VIDEO_DIR, relPath);
      if (!insideBase(VIDEO_DIR, abs)) return json(res, 403, { ok: false, error: "forbidden" });
      const ext = path.extname(abs).toLowerCase();
      if (!VIDEO_EXTS.has(ext)) return json(res, 400, { ok: false, error: "unsupported" });
      try {
        const st = await fsp.stat(abs);
        if (!st.isFile()) return json(res, 404, { ok: false, error: "not_found" });
      } catch {
        return json(res, 404, { ok: false, error: "not_found" });
      }

      if (ctx.user.role === "admin") {
        return json(res, 200, { ok: true, unlocked: true, quota: -1, unlockedCount: -1 });
      }

      const quota = Number(ctx.user.quota || 0);
      const unlocked = Array.isArray(ctx.user.unlocked) ? ctx.user.unlocked : [];
      const unlockedSet = new Set(unlocked.map(String));
      if (unlockedSet.has(relPath)) return json(res, 200, { ok: true, unlocked: true, quota, unlockedCount: unlockedSet.size });
      if (!Number.isFinite(quota) || quota <= 0) return json(res, 403, { ok: false, error: "no_quota", quota, unlockedCount: unlockedSet.size });
      if (unlockedSet.size >= quota) return json(res, 403, { ok: false, error: "quota_exceeded", quota, unlockedCount: unlockedSet.size });

      unlocked.push(relPath);
      ctx.user.unlocked = unlocked;
      await queueSaveUsers();
      return json(res, 200, { ok: true, unlocked: true, quota, unlockedCount: unlockedSet.size + 1 });
    }

    if (pathname === "/api/admin/users") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });
	      const users = usersDb.users
	        .map((u) => ({
	          username: u.username,
	          email: u.email || "",
	          role: u.role,
	          quota: u.quota,
	          unlockedCount: Array.isArray(u.unlocked) ? u.unlocked.length : 0,
	          emailVerified: u.email ? (u.emailVerified === false ? false : true) : true,
	          needsUsername: !!u.needsUsername,
	          createdAt: u.createdAt,
	          disabled: !!u.disabled,
	          accessUntilMs: u.accessUntilMs === null ? null : typeof u.accessUntilMs === "number" ? u.accessUntilMs : null,
	          accessRemainingMs:
	            typeof u.accessUntilMs === "number" ? Math.max(0, u.accessUntilMs - Date.now()) : null,
	          contentTokens: u.contentTokens ? u.contentTokens.length : 0,
	        }))
        .sort((a, b) => a.username.localeCompare(b.username));
      return json(res, 200, { ok: true, users });
    }

    if (pathname === "/api/admin/set-quota" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });
      const body = await readJson(req).catch(() => null);
      const username = cleanUsername(body && body.username);
      const quota = Number(body && body.quota);
      if (!username || !Number.isFinite(quota) || quota < 0 || quota > 1_000_000) {
        return json(res, 400, { ok: false, error: "bad_request" });
      }
      const user = usersDb.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
      if (!user) return json(res, 404, { ok: false, error: "not_found" });
      if (user.role === "admin") return json(res, 400, { ok: false, error: "cannot_change_admin" });
      user.quota = Math.floor(quota);
      await queueSaveUsers();
      return json(res, 200, { ok: true });
    }

    if (pathname === "/api/admin/update-user" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });
      const body = await readJson(req).catch(() => null);
      const username = cleanUsername(body && body.username);
      if (!username) return json(res, 400, { ok: false, error: "bad_request" });

      const user = usersDb.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
      if (!user) return json(res, 404, { ok: false, error: "not_found" });
      if (user.role === "admin") return json(res, 400, { ok: false, error: "cannot_change_admin" });

      if (body && Object.prototype.hasOwnProperty.call(body, "quota")) {
        const quota = Number(body.quota);
        if (!Number.isFinite(quota) || quota < 0 || quota > 1_000_000) return json(res, 400, { ok: false, error: "bad_quota" });
        user.quota = Math.floor(quota);
      }

      if (body && Object.prototype.hasOwnProperty.call(body, "accessMinutes")) {
        const mins = Number(body.accessMinutes);
        if (!Number.isFinite(mins) || mins < -1 || mins > 10_000_000) return json(res, 400, { ok: false, error: "bad_access_minutes" });
        if (mins < 0) {
          user.accessUntilMs = null;
        } else {
          user.accessUntilMs = Date.now() + Math.floor(mins) * 60_000;
        }
      }

      if (body && Object.prototype.hasOwnProperty.call(body, "disabled")) {
        user.disabled = !!body.disabled;
        if (user.disabled) {
          const now = new Date().toISOString();
          for (const s of sessionsDb.sessions) {
            if (s.uid !== user.id) continue;
            if (s.revokedAt) continue;
            s.revokedAt = now;
          }
          await queueSaveSessions();
        }
      }

      await queueSaveUsers();
      return json(res, 200, { ok: true });
    }

    if (pathname === "/api/admin/clear-unlocks" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });
      const body = await readJson(req).catch(() => null);
      const username = cleanUsername(body && body.username);
      if (!username) return json(res, 400, { ok: false, error: "bad_request" });
      const user = usersDb.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
      if (!user) return json(res, 404, { ok: false, error: "not_found" });
      if (user.role === "admin") return json(res, 400, { ok: false, error: "cannot_change_admin" });
      user.unlocked = [];
      await queueSaveUsers();
      return json(res, 200, { ok: true });
    }

    if (pathname === "/api/admin/sessions") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });
      const nowMs = Date.now();
      const onlineWindowMs = 60_000;
      const sessions = sessionsDb.sessions
        .map((s) => {
          const u = usersDb.users.find((x) => x.id === s.uid) || null;
          const lastSeenMs = s.lastSeenAt ? Date.parse(s.lastSeenAt) : 0;
          const online = !s.revokedAt && lastSeenMs && nowMs - lastSeenMs <= onlineWindowMs;
          return {
            id: s.id,
            username: u ? u.username : "(deleted)",
            email: u ? u.email || "" : "",
            uid: s.uid,
            deviceId: s.deviceId || "",
            deviceName: s.deviceName || "",
            userAgent: s.userAgent || "",
            ip: s.ip || "",
            createdAt: s.createdAt,
            lastSeenAt: s.lastSeenAt || null,
            revokedAt: s.revokedAt || null,
            online,
          };
        })
        .sort((a, b) => {
          if (a.online !== b.online) return a.online ? -1 : 1;
          const am = a.lastSeenAt ? Date.parse(a.lastSeenAt) : 0;
          const bm = b.lastSeenAt ? Date.parse(b.lastSeenAt) : 0;
          return bm - am;
        });
      return json(res, 200, { ok: true, sessions });
    }

    if (pathname === "/api/admin/chat/threads") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });

      const all = Array.isArray(chatDb.messages) ? chatDb.messages : [];
      const byUid = new Map(); // uid -> {uid,lastTs,lastText,lastFromRole,lastFromUsername}
      for (const m of all) {
        if (!m || typeof m.ts !== "number") continue;
        let uid = null;
        if (m.fromRole === "user" && typeof m.fromUid === "string") uid = m.fromUid;
        else if (m.toRole === "user" && typeof m.toUid === "string") uid = m.toUid;
        if (!uid) continue;
        const cur = byUid.get(uid) || { uid, lastTs: 0, lastText: "", lastFromRole: "", lastFromUsername: "" };
        if (m.ts >= cur.lastTs) {
          cur.lastTs = m.ts;
          cur.lastText = String(m.text || "");
          cur.lastFromRole = String(m.fromRole || "");
          cur.lastFromUsername = String(m.fromUsername || "");
        }
        byUid.set(uid, cur);
      }

      const nowMs = Date.now();
      const onlineWindowMs = 60_000;
      function isOnline(uid) {
        for (const s of sessionsDb.sessions) {
          if (!s || s.uid !== uid) continue;
          if (s.revokedAt) continue;
          const lastSeenMs = s.lastSeenAt ? Date.parse(s.lastSeenAt) : 0;
          if (lastSeenMs && nowMs - lastSeenMs <= onlineWindowMs) return true;
        }
        return false;
      }

      const uids = new Set();
      for (const u of usersDb.users) {
        if (!u || typeof u.id !== "string") continue;
        if (String(u.role || "") === "admin") continue;
        uids.add(u.id);
      }
      for (const uid of byUid.keys()) uids.add(uid);

      const threads = [...uids]
        .map((uid) => {
          const t = byUid.get(uid) || { uid, lastTs: 0, lastText: "", lastFromRole: "", lastFromUsername: "" };
          const u = usersDb.users.find((x) => x.id === uid) || null;
          return {
            uid,
            username: u ? u.username : "(deleted)",
            email: u ? u.email || "" : "",
            online: isOnline(uid),
            lastTs: t.lastTs,
            lastFromRole: t.lastFromRole,
            lastFromUsername: t.lastFromUsername,
            lastText: t.lastText.length > 300 ? t.lastText.slice(0, 300) : t.lastText,
          };
        })
        .sort((a, b) => {
          if (a.online !== b.online) return a.online ? -1 : 1;
          if (a.lastTs !== b.lastTs) return b.lastTs - a.lastTs;
          return String(a.username || "").localeCompare(String(b.username || ""));
        });

      return json(res, 200, { ok: true, threads, now: Date.now() });
    }

    if (pathname === "/api/admin/chat/history") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });

      const uid = sanitizeDeviceField(url.searchParams.get("uid"), 80);
      if (!uid) return json(res, 400, { ok: false, error: "bad_request" });
      const limitRaw = Number(url.searchParams.get("limit") || 120);
      const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(500, Math.floor(limitRaw))) : 120;

      const u = usersDb.users.find((x) => x.id === uid) || null;
      const all = Array.isArray(chatDb.messages) ? chatDb.messages : [];
      const filtered = all.filter((m) => m && (m.fromUid === uid || m.toUid === uid)).sort((a, b) => (a.ts || 0) - (b.ts || 0));
      const messages = filtered
        .slice(-limit)
        .map((m) => ({ id: m.id, ts: m.ts, fromRole: m.fromRole, fromUsername: m.fromUsername, text: m.text }));

      return json(res, 200, {
        ok: true,
        user: { uid, username: u ? u.username : "(deleted)", email: u ? u.email || "" : "" },
        messages,
        now: Date.now(),
      });
    }

    if (pathname === "/api/admin/chat/updates") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });

      const uid = sanitizeDeviceField(url.searchParams.get("uid"), 80);
      if (!uid) return json(res, 400, { ok: false, error: "bad_request" });
      const sinceRaw = Number(url.searchParams.get("since") || 0);
      const since = Number.isFinite(sinceRaw) ? Math.max(0, Math.floor(sinceRaw)) : 0;

      const all = Array.isArray(chatDb.messages) ? chatDb.messages : [];
      const messages = all
        .filter((m) => m && (m.fromUid === uid || m.toUid === uid) && typeof m.ts === "number" && m.ts > since)
        .sort((a, b) => (a.ts || 0) - (b.ts || 0))
        .slice(0, 500)
        .map((m) => ({ id: m.id, ts: m.ts, fromRole: m.fromRole, fromUsername: m.fromUsername, text: m.text }));

      return json(res, 200, { ok: true, messages, now: Date.now() });
    }

    if (pathname === "/api/admin/chat/send" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });

      const body = await readJson(req).catch(() => null);
      const uid = sanitizeDeviceField(body && body.uid, 80);
      const textRaw = String(body && body.text ? body.text : "").trim();
      if (!uid || !textRaw) return json(res, 400, { ok: false, error: "bad_request" });
      if (textRaw.length > 2000) return json(res, 400, { ok: false, error: "too_long" });

      const target = usersDb.users.find((u) => u.id === uid) || null;
      if (!target) return json(res, 404, { ok: false, error: "not_found" });

      const fromUid = ctx.kind === "user" ? ctx.user.id : "legacy";
      const fromUsername = ctx.kind === "user" ? ctx.user.username : "legacy-admin";
      addChatMessage({
        id: crypto.randomUUID(),
        ts: Date.now(),
        fromUid,
        fromUsername,
        fromRole: "admin",
        toUid: target.id,
        toRole: "user",
        text: textRaw,
      });

      return json(res, 200, { ok: true });
    }

    if (pathname === "/api/admin/revoke-session" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });
      const body = await readJson(req).catch(() => null);
      const sessionId = sanitizeDeviceField(body && body.sessionId, 80);
      if (!sessionId) return json(res, 400, { ok: false, error: "bad_request" });
      const s = sessionsDb.sessions.find((x) => x.id === sessionId);
      if (!s) return json(res, 404, { ok: false, error: "not_found" });
      if (!s.revokedAt) {
        s.revokedAt = new Date().toISOString();
        await queueSaveSessions();
      }
      return json(res, 200, { ok: true });
    }

    if (pathname === "/api/admin/revoke-user-sessions" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });
      const body = await readJson(req).catch(() => null);
      const username = cleanUsername(body && body.username);
      if (!username) return json(res, 400, { ok: false, error: "bad_request" });
      const user = usersDb.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
      if (!user) return json(res, 404, { ok: false, error: "not_found" });
      const now = new Date().toISOString();
      let count = 0;
      for (const s of sessionsDb.sessions) {
        if (s.uid !== user.id) continue;
        if (s.revokedAt) continue;
        s.revokedAt = now;
        count++;
      }
      if (count) await queueSaveSessions();
      return json(res, 200, { ok: true, revoked: count });
    }

    if (pathname === "/api/admin/delete-video" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });
      const body = await readJson(req).catch(() => null);
      let relPath;
      try {
        relPath = safeRelPathFromClient(body && body.path);
      } catch {
        return json(res, 400, { ok: false, error: "bad_path" });
      }
      const abs = path.resolve(VIDEO_DIR, relPath);
      if (!insideBase(VIDEO_DIR, abs)) return json(res, 403, { ok: false, error: "forbidden" });
      const ext = path.extname(abs).toLowerCase();
      if (!VIDEO_EXTS.has(ext)) return json(res, 400, { ok: false, error: "unsupported" });

      let st = null;
      try {
        st = await fsp.stat(abs);
        if (!st.isFile()) return json(res, 404, { ok: false, error: "not_found" });
      } catch {
        return json(res, 404, { ok: false, error: "not_found" });
      }

      // Cache key uses stat info, so compute before deletion.
      const key = cacheKeyForVideo(relPath, st);

      try {
        await fsp.unlink(abs);
      } catch {
        return json(res, 500, { ok: false, error: "delete_failed" });
      }

      // Remove from unlock lists.
      let unlockRemovals = 0;
      for (const u of usersDb.users) {
        if (!Array.isArray(u.unlocked) || u.unlocked.length === 0) continue;
        const before = u.unlocked.length;
        u.unlocked = u.unlocked.filter((p) => String(p) !== relPath);
        unlockRemovals += before - u.unlocked.length;
      }
      if (unlockRemovals) await queueSaveUsers();

      // Delete cached previews/thumbs for this file (best effort).
      try {
        const names = await fsp.readdir(CACHE_DIR);
        await Promise.all(
          names
            .filter((n) => n.startsWith(key))
            .map((n) => fsp.unlink(path.join(CACHE_DIR, n)).catch(() => {}))
        );
      } catch {
        // Ignore.
      }

      return json(res, 200, { ok: true, removedUnlocks: unlockRemovals });
    }

    if (pathname === "/api/content-tokens" && req.method === "GET") {
      const ctx = authContext(req, url);
      if (!ctx || ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (ctx.role !== "admin") return json(res, 403, { ok: false, error: "forbidden" });

      const tokens = Array.isArray(ctx.user.contentTokens) ? ctx.user.contentTokens : [];
      const out = tokens.map((t) => {
        const expMs = t && t.validUntil ? Date.parse(t.validUntil) : Date.now() + 7 * 24 * 60 * 60 * 1000;
        return {
          id: String(t.id || ""),
          name: String(t.name || ""),
          maxUses: Number(t.maxUses || 0),
          currentUses: Number(t.currentUses || 0),
          createdAt: String(t.createdAt || ""),
          validUntil: t.validUntil ? String(t.validUntil) : null,
          allowedVideos: Array.isArray(t.allowedVideos) ? t.allowedVideos.map(String) : null,
          token: makeContentTokenString(ctx.user.id, String(t.id || ""), expMs),
        };
      });
      out.sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
      return json(res, 200, { ok: true, contentTokens: out });
    }

    if (pathname === "/api/content-tokens" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx || ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (ctx.role !== "admin") return json(res, 403, { ok: false, error: "forbidden" });

      const body = await readJson(req).catch(() => null);
      const name = String(body && body.name ? body.name : "").trim();
      const maxUses = Number(body && body.maxUses);
      const validUntil = body && body.validUntil ? String(body.validUntil).trim() : "";
      const allowedVideosRaw = body && body.allowedVideos ? body.allowedVideos : null;

      if (!name || name.length > 80) return json(res, 400, { ok: false, error: "bad_name" });
      if (!Number.isFinite(maxUses) || maxUses <= 0 || maxUses > 1_000_000) return json(res, 400, { ok: false, error: "bad_max_uses" });

      let allowedVideos = null;
      if (Array.isArray(allowedVideosRaw) && allowedVideosRaw.length > 0) {
        try {
          allowedVideos = [...new Set(allowedVideosRaw.map((p) => safeRelPathFromClient(p)))];
        } catch {
          return json(res, 400, { ok: false, error: "bad_allowed_videos" });
        }
      }

      let expMs = Date.now() + 7 * 24 * 60 * 60 * 1000; // default 1 week
      if (validUntil) {
        if (/^\\d{4}-\\d{2}-\\d{2}$/.test(validUntil)) expMs = Date.parse(`${validUntil}T23:59:59.999Z`);
        else expMs = Date.parse(validUntil);
        if (!Number.isFinite(expMs)) return json(res, 400, { ok: false, error: "bad_valid_until" });
      }

      const tokenId = crypto.randomUUID();
      const now = new Date().toISOString();
      const rec = {
        id: tokenId,
        name,
        maxUses: Math.floor(maxUses),
        currentUses: 0,
        createdAt: now,
        validUntil: new Date(expMs).toISOString(),
        allowedVideos: allowedVideos || undefined,
        usedVideos: [],
      };
      if (!Array.isArray(ctx.user.contentTokens)) ctx.user.contentTokens = [];
      ctx.user.contentTokens.push(rec);
      await queueSaveUsers();

      return json(res, 200, {
        ok: true,
        id: rec.id,
        name: rec.name,
        maxUses: rec.maxUses,
        currentUses: rec.currentUses,
        createdAt: rec.createdAt,
        validUntil: rec.validUntil,
        allowedVideos: rec.allowedVideos || null,
        token: makeContentTokenString(ctx.user.id, rec.id, expMs),
      });
    }

    if (pathname === "/api/content-tokens/delete" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx || ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
      const inactive = authInactiveReason(ctx);
      if (inactive) return json(res, 403, { ok: false, error: inactive === "disabled" ? "account_disabled" : "access_expired" });
      if (ctx.role !== "admin") return json(res, 403, { ok: false, error: "forbidden" });

      const body = await readJson(req).catch(() => null);
      const tokenId = String(body && (body.tokenId || body.id) ? body.tokenId || body.id : "").trim();
      if (!tokenId) return json(res, 400, { ok: false, error: "bad_request" });

      const tokens = Array.isArray(ctx.user.contentTokens) ? ctx.user.contentTokens : [];
      const idx = tokens.findIndex((t) => String(t.id || "") === tokenId);
      if (idx < 0) return json(res, 404, { ok: false, error: "not_found" });
      tokens.splice(idx, 1);
      ctx.user.contentTokens = tokens;
      await queueSaveUsers();
      return json(res, 200, { ok: true });
    }

    if (pathname.startsWith("/thumb/")) {
      const ctx = authContext(req, url);
      if (!ctx) return text(res, 401, "unauthorized\n");
      const inactive = authInactiveReason(ctx);
      if (inactive) return text(res, 403, `${inactive === "disabled" ? "account_disabled" : "access_expired"}\n`);
      const rel = pathname.slice("/thumb/".length);
      let abs;
      let relDecoded;
      try {
        ({ abs, relDecoded } = await resolveVideoFromUrlPath(rel));
      } catch (err) {
        return text(res, 400, `${err.message}\n`);
      }
      if (ctx.tokenInfo) {
        const allowed = Array.isArray(ctx.tokenInfo.allowedVideos) ? ctx.tokenInfo.allowedVideos.map(String) : [];
        if (allowed.length && !allowed.includes(relDecoded)) return text(res, 403, "forbidden\n");
      }
      const thumb = await ensureThumb(abs, relDecoded);
      const buf = await fsp.readFile(thumb);
      res.writeHead(200, {
        "Content-Type": "image/jpeg",
        "Content-Length": buf.length,
        "Cache-Control": "no-store",
      });
      if (req.method === "HEAD") return res.end();
      return res.end(buf);
    }

    if (pathname.startsWith("/preview/")) {
      const ctx = authContext(req, url);
      if (!ctx) return text(res, 401, "unauthorized\n");
      const inactive = authInactiveReason(ctx);
      if (inactive) return text(res, 403, `${inactive === "disabled" ? "account_disabled" : "access_expired"}\n`);
      const rel = pathname.slice("/preview/".length);
      let abs;
      let relDecoded;
      try {
        ({ abs, relDecoded } = await resolveVideoFromUrlPath(rel));
      } catch (err) {
        return text(res, 400, `${err.message}\n`);
      }
      if (ctx.tokenInfo) {
        const allowed = Array.isArray(ctx.tokenInfo.allowedVideos) ? ctx.tokenInfo.allowedVideos.map(String) : [];
        if (allowed.length && !allowed.includes(relDecoded)) return text(res, 403, "forbidden\n");
      }
      const prev = await ensurePreview(abs, relDecoded);
      return serveFile(req, res, prev, { contentType: "video/mp4" });
    }

    if (pathname.startsWith("/media/") || pathname.startsWith("/download/")) {
      const isDownload = pathname.startsWith("/download/");
      const prefix = isDownload ? "/download/" : "/media/";
      const ctx = authContext(req, url);
      if (!ctx) return text(res, 401, "unauthorized\n");
      const inactive = authInactiveReason(ctx);
      if (inactive) return text(res, 403, `${inactive === "disabled" ? "account_disabled" : "access_expired"}\n`);

      const rel = pathname.slice(prefix.length);
      let abs;
      let relDecoded;
      try {
        ({ abs, relDecoded } = await resolveVideoFromUrlPath(rel));
      } catch (err) {
        return text(res, 400, `${err.message}\n`);
      }

      // Content token access (no login).
      if (ctx.tokenInfo) {
        const token = ctx.tokenInfo;
        const allowed = Array.isArray(token.allowedVideos) ? token.allowedVideos.map(String) : [];
        if (allowed.length && !allowed.includes(relDecoded)) return text(res, 403, "forbidden\n");

        let used = Array.isArray(token.usedVideos) ? token.usedVideos : [];
        const usedSet = new Set(used.map(String));

        const maxUses = Number(token.maxUses);
        const unlimited = Number.isFinite(maxUses) && maxUses < 0;

        if (!usedSet.has(relDecoded)) {
          if (!unlimited) {
            if (!Number.isFinite(maxUses) || maxUses <= 0 || usedSet.size >= maxUses) return text(res, 403, "token_exhausted\n");
          }
          used.push(relDecoded);
          token.usedVideos = used;
          token.currentUses = usedSet.size + 1;
          await queueSaveUsers();
        }

        const name = path.basename(abs);
        return serveFile(req, res, abs, isDownload ? { downloadName: name } : {});
      }

      // Legacy token or admin user can access everything.
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) {
        const unlockedSet = new Set((ctx.user.unlocked || []).map(String));
        if (!unlockedSet.has(relDecoded)) return text(res, 403, "locked\n");
      }

      const name = path.basename(abs);
      return serveFile(req, res, abs, isDownload ? { downloadName: name } : {});
    }

    return text(res, 404, "Not found\n");
  } catch (err) {
    console.error(err);
    return text(res, 500, "Server error\n");
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Camfordick server running`);
  console.log(`VIDEO_DIR: ${VIDEO_DIR}`);
  for (const u of localUrls(PORT)) console.log(`  ${u}`);
});
