#!/usr/bin/env node
"use strict";

const http = require("http");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawn } = require("child_process");

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
/** @type {{users: Array<{id:string,username:string,role:"admin"|"user",salt:string,passHash:string,quota:number,unlocked:string[],createdAt:string}>}} */
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

function json(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj, null, 2));
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function text(res, status, body, contentType = "text/plain; charset=utf-8") {
  const buf = Buffer.from(body);
  res.writeHead(status, {
    "Content-Type": contentType,
    "Content-Length": buf.length,
    "Cache-Control": "no-store",
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

function makeAuthToken(user) {
  const expMs = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  const payload = { uid: user.id, exp: expMs };
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
  return user;
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
  if (!tok) return null;

  const user = verifyAuthToken(tok);
  if (!user) return null;
  return { kind: "user", role: user.role, user };
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

    if (pathname === "/" || pathname === "/index.html") return serveIndex(req, res);

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
        createdAt: new Date().toISOString(),
      };
      usersDb.users.push(user);
      await queueSaveUsers();

      const auth = makeAuthToken(user);
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

      const auth = makeAuthToken(user);
      return json(res, 200, { ok: true, user: { username: user.username, role: user.role, quota: user.quota }, auth });
    }

    if (pathname === "/api/me") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      if (ctx.kind === "legacy") return json(res, 200, { ok: true, user: { username: "legacy-token", role: "admin", quota: -1, unlockedCount: -1 } });
      const u = ctx.user;
      return json(res, 200, {
        ok: true,
        user: {
          username: u.username,
          role: u.role,
          quota: u.quota,
          unlockedCount: Array.isArray(u.unlocked) ? u.unlocked.length : 0,
        },
      });
    }

    if (pathname === "/api/videos") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      const videos = await listVideosRecursive(VIDEO_DIR);
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
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });
      const users = usersDb.users
        .map((u) => ({
          username: u.username,
          role: u.role,
          quota: u.quota,
          unlockedCount: Array.isArray(u.unlocked) ? u.unlocked.length : 0,
          createdAt: u.createdAt,
        }))
        .sort((a, b) => a.username.localeCompare(b.username));
      return json(res, 200, { ok: true, users });
    }

    if (pathname === "/api/admin/set-quota" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
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

    if (pathname.startsWith("/thumb/")) {
      const ctx = authContext(req, url);
      if (!ctx) return text(res, 401, "unauthorized\n");
      const rel = pathname.slice("/thumb/".length);
      let abs;
      let relDecoded;
      try {
        ({ abs, relDecoded } = await resolveVideoFromUrlPath(rel));
      } catch (err) {
        return text(res, 400, `${err.message}\n`);
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
      const rel = pathname.slice("/preview/".length);
      let abs;
      let relDecoded;
      try {
        ({ abs, relDecoded } = await resolveVideoFromUrlPath(rel));
      } catch (err) {
        return text(res, 400, `${err.message}\n`);
      }
      const prev = await ensurePreview(abs, relDecoded);
      return serveFile(req, res, prev, { contentType: "video/mp4" });
    }

    if (pathname.startsWith("/media/") || pathname.startsWith("/download/")) {
      const isDownload = pathname.startsWith("/download/");
      const prefix = isDownload ? "/download/" : "/media/";
      const ctx = authContext(req, url);
      if (!ctx) return text(res, 401, "unauthorized\n");

      const rel = pathname.slice(prefix.length);
      let abs;
      let relDecoded;
      try {
        ({ abs, relDecoded } = await resolveVideoFromUrlPath(rel));
      } catch (err) {
        return text(res, 400, `${err.message}\n`);
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
