#!/usr/bin/env node
"use strict";

const http = require("http");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawn } = require("child_process");
const nodemailer = require("nodemailer");

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

// Magic link (passwordless email login)
const MAGIC_LINK_EXPIRY_MS = 15 * 60 * 1000; // 15 minutes
const MAGIC_LINK_RATE_LIMIT = 3; // per IP per window
const MAGIC_LINK_RATE_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const SMTP_HOST = String(process.env.SMTP_HOST || "").trim();
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = process.env.SMTP_SECURE === "1" || process.env.SMTP_SECURE === "true";
const SMTP_USER = String(process.env.SMTP_USER || "").trim();
const SMTP_PASS = String(process.env.SMTP_PASS || "").trim();
const MAIL_FROM = String(process.env.MAIL_FROM || "noreply@localhost").trim();
const MAGIC_LINK_ENABLED = !!(SMTP_HOST && SMTP_USER && SMTP_PASS);
const ALLOWED_RETURN_ORIGINS = (() => {
  const raw = String(process.env.ALLOWED_RETURN_ORIGINS || "").trim();
  if (!raw) return new Set();
  return new Set(raw.split(",").map((s) => s.trim()).filter(Boolean));
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

// Magic link: pending tokens (jti -> { email, exp }), one-time use; cleared on use or expiry
const magicPending = new Map();
const magicRateLimit = new Map(); // ip -> { count, firstAt }

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
  if (!user.salt || !user.passHash) return false;
  const derived = await scryptAsync(password, Buffer.from(user.salt, "hex"));
  const expected = Buffer.from(user.passHash, "hex");
  if (expected.length !== derived.length) return false;
  return crypto.timingSafeEqual(expected, derived);
}

function normalizeEmail(raw) {
  const s = String(raw || "").trim().toLowerCase();
  if (s.length < 3 || s.length > 254) return null;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) return null;
  return s;
}

function createMagicToken(email) {
  const jti = crypto.randomUUID();
  const exp = Date.now() + MAGIC_LINK_EXPIRY_MS;
  const payload = { email, exp, jti };
  const payloadB64 = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(payloadB64).digest();
  magicPending.set(jti, { email, exp });
  return { token: `${payloadB64}.${b64url(sig)}`, jti };
}

function verifyAndConsumeMagicToken(tokenStr) {
  const t = String(tokenStr || "").trim();
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
  if (!payload || typeof payload.email !== "string" || typeof payload.exp !== "number" || typeof payload.jti !== "string") return null;
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
  const pending = magicPending.get(payload.jti);
  if (!pending || pending.email !== payload.email) return null;
  magicPending.delete(payload.jti);
  return { email: payload.email };
}

function checkMagicLinkRateLimit(ip) {
  const now = Date.now();
  let entry = magicRateLimit.get(ip);
  if (!entry) {
    magicRateLimit.set(ip, { count: 1, firstAt: now });
    return true;
  }
  if (now - entry.firstAt > MAGIC_LINK_RATE_WINDOW_MS) {
    magicRateLimit.set(ip, { count: 1, firstAt: now });
    return true;
  }
  if (entry.count >= MAGIC_LINK_RATE_LIMIT) return false;
  entry.count++;
  return true;
}

function validateReturnTo(returnTo, requestOrigin) {
  if (!returnTo || typeof returnTo !== "string") return null;
  const s = returnTo.trim();
  if (!s) return null;
  try {
    const u = new URL(s);
    const req = new URL(requestOrigin);
    if (u.origin === req.origin) return s;
    if (ALLOWED_RETURN_ORIGINS.size && ALLOWED_RETURN_ORIGINS.has(u.origin)) return s;
    return null;
  } catch {
    return null;
  }
}

async function sendMagicLinkEmail(to, magicLink) {
  const transport = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
  });
  await transport.sendMail({
    from: MAIL_FROM,
    to,
    subject: "Sign in to Camfordick",
    text: `Click the link below to sign in. This link expires in 15 minutes.\n\n${magicLink}\n\nIf you didn't request this, you can ignore this email.`,
  });
}

async function findOrCreateUserByEmail(email) {
  const normalized = normalizeEmail(email);
  if (!normalized) return null;
  let user = usersDb.users.find((u) => u.email && u.email.toLowerCase() === normalized);
  if (user) return user;
  const role = usersDb.users.length === 0 ? "admin" : "user";
  const usernameFromEmail = normalized.replace(/@.*/, "").replace(/[^a-zA-Z0-9_.-]/g, "_").slice(0, 32) || "user";
  let username = usernameFromEmail;
  let suffix = 0;
  while (usersDb.users.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
    suffix++;
    username = `${usernameFromEmail.slice(0, 28)}_${suffix}`;
  }
  user = {
    id: crypto.randomUUID(),
    username,
    email: normalized,
    role,
    salt: "",
    passHash: "",
    quota: role === "admin" ? -1 : 0,
    unlocked: [],
    contentTokens: [],
    disabled: false,
    accessUntilMs: null,
    createdAt: new Date().toISOString(),
  };
  usersDb.users.push(user);
  await queueSaveUsers();
  return user;
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
          magicLinkEnabled: MAGIC_LINK_ENABLED,
          previewSeconds: PREVIEW_SECONDS,
        },
        now: new Date().toISOString(),
      });
    }

    if (pathname === "/api/auth/signup" && req.method === "POST") {
      if (!SIGNUP_ENABLED) return json(res, 403, { ok: false, error: "signup_disabled" });
      const body = await readJson(req).catch(() => null);
      const username = cleanUsername(body && body.username);
      const password = normalizePassword(body && body.password);
      if (!username || !password) return json(res, 400, { ok: false, error: "bad_request" });

      if (usersDb.users.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
        return json(res, 409, { ok: false, error: "username_taken" });
      }

      const salt = crypto.randomBytes(16);
      const derived = await scryptAsync(password, salt);
      /** @type {"admin" | "user"} */
      const role = usersDb.users.length === 0 ? "admin" : "user";
      const user = {
        id: crypto.randomUUID(),
        username,
        role,
        salt: salt.toString("hex"),
        passHash: derived.toString("hex"),
        quota: role === "admin" ? -1 : 0,
        unlocked: [],
        contentTokens: [], // Initialize content tokens array
        disabled: false,
        accessUntilMs: null,
        createdAt: new Date().toISOString(),
      };
      usersDb.users.push(user);
      await queueSaveUsers();

      const session = createSessionForUser(user, { deviceId: body && body.deviceId, deviceName: body && body.deviceName, req });
      await queueSaveSessions();
      const auth = makeAuthToken(user, session.id);
      return json(res, 200, { ok: true, user: { username: user.username, role: user.role, quota: user.quota }, auth });
    }

    if (pathname === "/api/auth/login" && req.method === "POST") {
      const body = await readJson(req).catch(() => null);
      const username = cleanUsername(body && body.username);
      const password = normalizePassword(body && body.password);
      if (!username || !password) return json(res, 400, { ok: false, error: "bad_request" });

      const user = usersDb.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
      if (!user) return json(res, 401, { ok: false, error: "invalid_credentials" });
      const ok = await verifyPassword(user, password).catch(() => false);
      if (!ok) return json(res, 401, { ok: false, error: "invalid_credentials" });

      if (user.disabled) return json(res, 403, { ok: false, error: "account_disabled" });
      if (typeof user.accessUntilMs === "number" && Date.now() > user.accessUntilMs) return json(res, 403, { ok: false, error: "access_expired" });

      const session = createSessionForUser(user, { deviceId: body && body.deviceId, deviceName: body && body.deviceName, req });
      await queueSaveSessions();
      const auth = makeAuthToken(user, session.id);
      return json(res, 200, { ok: true, user: { username: user.username, role: user.role, quota: user.quota }, auth });
    }

    if (pathname === "/api/auth/magic-link" && req.method === "POST") {
      if (!MAGIC_LINK_ENABLED) return json(res, 503, { ok: false, error: "magic_link_not_configured" });
      const body = await readJson(req).catch(() => null);
      const email = normalizeEmail(body && body.email);
      if (!email) return json(res, 400, { ok: false, error: "bad_request" });
      const ip = getClientIp(req);
      if (!checkMagicLinkRateLimit(ip)) return json(res, 429, { ok: false, error: "too_many_requests" });
      const { token } = createMagicToken(email);
      const proto = String(req.headers["x-forwarded-proto"] || "http").split(",")[0].trim();
      const host = req.headers.host || "localhost";
      const origin = `${proto}://${host}`;
      const returnTo = validateReturnTo(body && body.return_to, origin) || `${origin}/`;
      const magicLink = `${origin}/api/auth/magic?token=${encodeURIComponent(token)}&return_to=${encodeURIComponent(returnTo)}`;
      try {
        await sendMagicLinkEmail(email, magicLink);
      } catch (err) {
        console.error("Magic link email failed:", err);
        return json(res, 500, { ok: false, error: "email_failed" });
      }
      return json(res, 200, { ok: true });
    }

    if (pathname === "/api/auth/magic" && req.method === "GET") {
      const tokenStr = url.searchParams.get("token");
      const returnToParam = url.searchParams.get("return_to");
      const proto = String(req.headers["x-forwarded-proto"] || "http").split(",")[0].trim();
      const host = req.headers.host || "localhost";
      const origin = `${proto}://${host}`;
      const safeReturnTo = validateReturnTo(returnToParam, origin) || `${origin}/`;
      const result = verifyAndConsumeMagicToken(tokenStr);
      if (!result) {
        res.writeHead(302, { Location: `${safeReturnTo}#error=invalid_or_expired_link` });
        return res.end();
      }
      const user = await findOrCreateUserByEmail(result.email);
      if (!user) {
        res.writeHead(302, { Location: `${safeReturnTo}#error=invalid_email` });
        return res.end();
      }
      if (user.disabled) {
        res.writeHead(302, { Location: `${safeReturnTo}#error=account_disabled` });
        return res.end();
      }
      if (typeof user.accessUntilMs === "number" && Date.now() > user.accessUntilMs) {
        res.writeHead(302, { Location: `${safeReturnTo}#error=access_expired` });
        return res.end();
      }
      const session = createSessionForUser(user, { deviceId: undefined, deviceName: "magic-link", req });
      await queueSaveSessions();
      const auth = makeAuthToken(user, session.id);
      res.writeHead(302, { Location: `${safeReturnTo}#auth=${encodeURIComponent(auth)}` });
      return res.end();
    }

    if (pathname === "/api/me") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      if (ctx.kind === "legacy") return json(res, 200, { ok: true, user: { username: "legacy-token", role: "admin", quota: -1, unlockedCount: -1 } });
      if (ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
      const u = ctx.user;
      const accessUntilMs = u.accessUntilMs === null ? null : typeof u.accessUntilMs === "number" ? u.accessUntilMs : null;
      const accessRemainingMs = typeof accessUntilMs === "number" ? Math.max(0, accessUntilMs - Date.now()) : null;
      return json(res, 200, {
        ok: true,
        inactive: authInactiveReason(ctx),
        user: {
          username: u.username,
          role: u.role,
          quota: u.quota,
          unlockedCount: Array.isArray(u.unlocked) ? u.unlocked.length : 0,
          disabled: !!u.disabled,
          accessUntilMs,
          accessRemainingMs,
          contentTokens: u.contentTokens || [],
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
          user: { role: "token-user", quota: unlimited ? -1 : Number.isFinite(maxUses) ? Math.floor(maxUses) : 0, unlockedCount: usedSet.size },
        });
      }
      
      if (ctx.kind === "legacy" || ctx.role === "admin") {
        const list = videos.map((v) => ({ ...v, unlocked: true }));
        return json(res, 200, { ok: true, count: list.length, videos: list, user: { role: "admin", quota: -1, unlockedCount: -1 } });
      }
      const unlockedSet = new Set((ctx.user.unlocked || []).map(String));
      const list = videos.map((v) => ({ ...v, unlocked: unlockedSet.has(v.path) }));
      return json(res, 200, {
        ok: true,
        count: list.length,
        videos: list,
        user: {
          username: ctx.user.username,
          role: ctx.user.role,
          quota: ctx.user.quota,
          unlockedCount: unlockedSet.size,
        },
      });
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
          role: u.role,
          quota: u.quota,
          unlockedCount: Array.isArray(u.unlocked) ? u.unlocked.length : 0,
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
