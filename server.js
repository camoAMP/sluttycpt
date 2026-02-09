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
// Optional: link shown in the UI for "Buy" / checkout / WhatsApp.
const BUY_URL = String(process.env.BUY_URL || "").trim();

const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(process.cwd(), ".camfordick-data"));
const CACHE_DIR = path.resolve(process.env.CACHE_DIR || path.join(process.cwd(), ".camfordick-cache"));

const PREVIEW_SECONDS = Math.max(1, Math.min(60, Number(process.env.PREVIEW_SECONDS || 10)));
const SIGNUP_ENABLED = process.env.SIGNUP_ENABLED === "0" ? false : true;
const SESSION_DAYS = Math.max(1, Math.min(365, Number(process.env.SESSION_DAYS || 30)));

const VIDEO_EXTS = new Set([".mp4", ".webm", ".mkv", ".avi", ".mov", ".m4v"]);

// Pricing + loyalty info is displayed by the UI (optional; no built-in payments).
const PRICING_BUNDLES = [
  { id: "10min", minutes: 10, priceZar: 100 },
  { id: "15min", minutes: 15, priceZar: 150 },
  { id: "30min", minutes: 30, priceZar: 250 },
  { id: "45min", minutes: 45, priceZar: 350 },
  { id: "1hour", minutes: 60, priceZar: 450 },
];

const LOYALTY_TIERS = [
  { id: "bronze", name: "Bronze", minSpentZar: 500, discountPct: 10, perks: ["10% off next purchase"] },
  { id: "silver", name: "Silver", minSpentZar: 2000, discountPct: 20, perks: ["20% off next", "Free 10min bundle"] },
  { id: "gold", name: "Gold", minSpentZar: 5000, discountPct: 30, perks: ["30% off next", "Customs discount"] },
];

function normalizeMoneyZar(n) {
  const x = Number(n);
  if (!Number.isFinite(x) || x < 0) return 0;
  return Math.round(x);
}

function loyaltyForUser(user) {
  const spentZar = normalizeMoneyZar(user && user.spentZar);
  const points = Math.max(0, Math.floor(Number.isFinite(Number(user && user.points)) ? Number(user.points) : spentZar / 10));
  let tier = null;
  for (const t of LOYALTY_TIERS) {
    if (spentZar >= t.minSpentZar) tier = t;
  }
  return { spentZar, points, tier };
}

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
/** @type {{users: Array<{id:string,username:string,role:"admin"|"user",salt:string,passHash:string,quota:number,unlocked:string[],contentTokens?:Array<{id:string, name:string, maxUses:number, currentUses:number, createdAt:string, validUntil?:string, allowedVideos?:string[], bundleType?:string}>,createdAt:string}>}} */
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

function makeAuthToken(user) {
  const expMs = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  const payload = { uid: user.id, exp: expMs };
  const payloadB64 = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(payloadB64).digest();
  return `${payloadB64}.${b64url(sig)}`;
}

function makeContentToken(userId, tokenName, maxUses, validUntil, allowedVideos, bundleType) {
  const expMs = validUntil ? new Date(validUntil).getTime() : Date.now() + 7 * 24 * 60 * 60 * 1000; // default 1 week
  const tokenId = crypto.randomUUID();
  const payload = { tid: tokenId, uid: userId, exp: expMs, bundleType };
  const payloadB64 = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(payloadB64).digest();
  return {
    token: `${payloadB64}.${b64url(sig)}`,
    tokenId,
    name: tokenName,
    maxUses,
    validUntil: new Date(expMs).toISOString(),
    allowedVideos,
    bundleType
  };
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
  
  // Find the specific token in the user's tokens
  const userToken = (user.contentTokens || []).find((t) => String(t && t.id) === payload.tid);
  if (!userToken) return null;

  const maxUses = Math.max(1, Math.floor(Number(userToken.maxUses || 0)));
  const currentField = Math.max(0, Math.floor(Number(userToken.currentUses || 0)));
  const usedLen = Array.isArray(userToken.usedVideos) ? userToken.usedVideos.length : 0;
  const uses = Math.max(currentField, usedLen);
  if (uses >= maxUses) return null;

  // Normalize fields so callers/UI can rely on them.
  userToken.maxUses = maxUses;
  userToken.currentUses = uses;
  
  return { user, tokenInfo: userToken };
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
    const d = encodeURIComponent(p);
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
  /** @type {{path:string,name:string,ext:string,size:number,mtimeMs:number,duration?:number}[]} */
  const out = [];

  async function walk(absDir, relPrefix) {
    let entries;
    try {
      entries = await fsp.readdir(absDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const ent of entries) {
      // Skip hidden files/folders (e.g. ".trashed-...", ".nomedia").
      // Users often have these in phone-synced folders and they clutter the UI.
      if (ent.name && ent.name.startsWith(".")) continue;
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
        duration: undefined // We'll calculate this later if possible
      });
    }
  }

  await walk(baseDir, "");
  out.sort((a, b) => a.path.localeCompare(b.path));
  return out;
}

async function estimateVideoDuration(filePath) {
  // Try to get duration using ffprobe if available, otherwise use ffmpeg
  try {
    const { spawn } = require('child_process');
    return await new Promise((resolve, reject) => {
      const child = spawn('ffprobe', [
        '-v', 'quiet',
        '-print_format', 'json',
        '-show_format',
        filePath
      ]);

      let output = '';
      child.stdout.on('data', (data) => {
        output += data.toString();
      });

      child.on('close', (code) => {
        if (code === 0) {
          try {
            const result = JSON.parse(output);
            const duration = parseFloat(result.format.duration);
            resolve(duration);
          } catch (e) {
            reject(e);
          }
        } else {
          reject(new Error(`ffprobe failed with code ${code}`));
        }
      });

      child.on('error', reject);
    });
  } catch (e) {
    // If ffprobe is not available, we'll return a default duration
    console.error("Error getting video duration:", e.message);
    return 300; // Default to 5 minutes if we can't determine duration
  }
}

async function createBundleVideos(videos, bundleType) {
  // Define bundle durations in seconds
  const bundleDurations = {
    '10min': 10 * 60,
    '15min': 15 * 60,
    '30min': 30 * 60,
    '45min': 45 * 60,
    '1hour': 60 * 60
  };

  // If we don't have duration info, try to get it
  const videosWithDuration = await Promise.all(
    videos.map(async (video) => {
      if (video.duration !== undefined) {
        return video;
      }
      try {
        const absPath = path.join(VIDEO_DIR, video.path);
        const duration = await estimateVideoDuration(absPath);
        return { ...video, duration };
      } catch (e) {
        // If we can't get duration, default to 5 minutes
        return { ...video, duration: 300 };
      }
    })
  );

  // Filter out videos with invalid durations
  const validVideos = videosWithDuration.filter(v => v.duration > 0);

  // Calculate target duration in seconds
  const targetDuration = bundleDurations[bundleType];
  if (!targetDuration) {
    throw new Error(`Invalid bundle type: ${bundleType}`);
  }

  // Sort videos by duration (shortest first) to optimize packing
  validVideos.sort((a, b) => a.duration - b.duration);

  // Simple greedy algorithm to create a bundle close to target duration
  const bundleVideos = [];
  let totalDuration = 0;

  for (const video of validVideos) {
    if (totalDuration + video.duration <= targetDuration) {
      bundleVideos.push(video);
      totalDuration += video.duration;
    } else {
      // If adding this video would exceed the target, check if we're close enough
      // Otherwise, continue to see if there's a smaller video that fits
      continue;
    }
  }

  // If we couldn't get close to the target duration, try to add more videos
  // up to a reasonable tolerance (e.g., 10% over target)
  const tolerance = targetDuration * 0.1; // 10% tolerance
  for (const video of validVideos) {
    if (bundleVideos.some(v => v.path === video.path)) continue; // Skip already added
    
    if (totalDuration + video.duration <= targetDuration + tolerance) {
      bundleVideos.push(video);
      totalDuration += video.duration;
    }
  }

  return {
    videos: bundleVideos.map(v => v.path),
    totalDuration: totalDuration,
    targetDuration: targetDuration
  };
}

async function serveIndex(req, res) {
  try {
    const buf = await fsp.readFile(INDEX_FILE);
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Length": buf.length,
      "Cache-Control": "no-store",
      // Anti-piracy headers
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "same-origin",
      // NOTE: Do not set COEP/COOP on the HTML shell when using Tailwind CDN.
      // COEP require-corp will block cross-origin scripts that don't send CORP/CORS headers
      // (e.g. https://cdn.tailwindcss.com), causing the UI to appear "unstyled".
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
  // Anti-piracy headers to prevent direct downloads and recording
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cross-Origin-Resource-Policy", "same-site");
  res.setHeader("Permissions-Policy", "microphone=(), camera=()");
  res.setHeader("Content-Security-Policy", "default-src 'self'; media-src 'self'; object-src 'none'; frame-src 'none';");
  
  if (downloadName) {
    res.setHeader("Content-Disposition", `attachment; filename="${String(downloadName).replace(/\"/g, "")}"`);
  }

  const range = req.headers.range;
  if (!range) {
    res.statusCode = 200;
    res.setHeader("Content-Length", size);
    if (req.method === "HEAD") return res.end();
    
    // Track content usage for anti-piracy purposes
    const userAgent = req.headers['user-agent'] || '';
    console.log(`Content served: ${abs}, User-Agent: ${userAgent}`);
    
    const readStream = fs.createReadStream(abs);
    readStream.on('error', (err) => {
      console.error(`Error streaming file ${abs}:`, err);
      if (!res.headersSent) {
        text(res, 500, "Internal server error\n");
      }
    });
    readStream.pipe(res);
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
  
  // Track content usage for anti-piracy purposes
  const userAgent = req.headers['user-agent'] || '';
  console.log(`Content served (partial): ${abs}, User-Agent: ${userAgent}`);
  
  const readStream = fs.createReadStream(abs, { start, end });
  readStream.on('error', (err) => {
    console.error(`Error streaming partial file ${abs}:`, err);
    if (!res.headersSent) {
      text(res, 500, "Internal server error\n");
    }
  });
  readStream.pipe(res);
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
  return new Promise((resolve, reject) => {
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
	      const ct = verifyContentToken(contentToken);
	      if (!ct) return null;
	      return { kind: "contentToken", role: "token-user", user: ct.user, tokenInfo: ct.tokenInfo };
	    }
	    return null;
	  }

  const user = verifyAuthToken(tok);
  if (!user) return null;
  return { kind: "user", role: user.role, user };
}

function tokenAllowsVideo(tokenInfo, relPath) {
  const allowed = tokenInfo && tokenInfo.allowedVideos;
  if (!Array.isArray(allowed) || allowed.length === 0) return true;
  return allowed.map(String).includes(String(relPath));
}

function tokenUses(tokenInfo) {
  if (!tokenInfo) return { current: 0, max: 0 };
  const max = Math.max(1, Math.floor(Number(tokenInfo.maxUses || 0)));
  const currentField = Math.max(0, Math.floor(Number(tokenInfo.currentUses || 0)));
  const usedLen = Array.isArray(tokenInfo.usedVideos) ? tokenInfo.usedVideos.length : 0;
  const current = Math.max(currentField, usedLen);
  return { current, max };
}

async function consumeTokenVideoUse(user, tokenInfo, relPath) {
  if (!user || !tokenInfo) return { ok: false, error: "bad_token" };
  const used = Array.isArray(tokenInfo.usedVideos) ? tokenInfo.usedVideos : [];
  const p = String(relPath || "");
  if (!p) return { ok: false, error: "bad_path" };

  const { current, max } = tokenUses(tokenInfo);
  if (used.includes(p)) return { ok: true, consumed: false, current, max };
  if (current >= max) return { ok: false, error: "token_exhausted", current, max };

  used.push(p);
  tokenInfo.usedVideos = used;
  tokenInfo.currentUses = current + 1;
  tokenInfo.lastUsedAt = new Date().toISOString();
  await queueSaveUsers();
  return { ok: true, consumed: true, current: current + 1, max };
}

// Create the HTTP server with improved connection handling
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const { pathname } = url;

    // Basic CORS for API/media if someone hosts index.html elsewhere.
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST");
    res.setHeader("Access-Control-Allow-Headers", "Range,Content-Type,Authorization");
    // Anti-piracy headers
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    res.setHeader("X-Content-Type-Options", "nosniff");
    if (req.method === "OPTIONS") return res.end();

    // Serve the SPA shell for the root and the admin route.
    // The client-side code uses location.pathname to toggle admin UI.
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
        buyUrl: BUY_URL || null,
        pricing: {
          currency: "ZAR",
          bundles: PRICING_BUNDLES,
          loyaltyTiers: LOYALTY_TIERS,
        },
        auth: {
          legacyToken: LEGACY_TOKEN ? true : false,
          users: true,
          signupEnabled: SIGNUP_ENABLED,
          previewSeconds: PREVIEW_SECONDS,
        },
        now: new Date().toISOString(),
        bundles: PRICING_BUNDLES.map((b) => b.id), // Available bundle types
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
        spentZar: 0,
        points: 0,
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
      if (ctx.kind === "contentToken") {
        const ti = ctx.tokenInfo || {};
        const maxUses = Math.max(1, Math.floor(Number(ti.maxUses || 0)));
        const usesField = Math.max(0, Math.floor(Number(ti.currentUses || 0)));
        const usedLen = Array.isArray(ti.usedVideos) ? ti.usedVideos.length : 0;
        const uses = Math.max(usesField, usedLen);
        return json(res, 200, {
          ok: true,
          user: {
            username: String(ti.name || "token"),
            role: "token-user",
            quota: -1,
            unlockedCount: -1,
            token: {
              id: String(ti.id || ""),
              name: String(ti.name || ""),
              maxUses,
              currentUses: uses,
              validUntil: ti.validUntil || undefined,
              bundleType: ti.bundleType || undefined,
            },
          },
        });
      }
      const u = ctx.user;
      const loy = loyaltyForUser(u);
      return json(res, 200, {
        ok: true,
        user: {
          username: u.username,
          role: u.role,
          quota: u.quota,
          unlockedCount: Array.isArray(u.unlocked) ? u.unlocked.length : 0,
          contentTokens: u.contentTokens || [],
          spentZar: loy.spentZar,
          points: loy.points,
          tier: loy.tier
            ? { id: loy.tier.id, name: loy.tier.name, discountPct: loy.tier.discountPct, perks: loy.tier.perks }
            : null,
        },
      });
    }

    if (pathname === "/api/videos") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      
      const videos = await listVideosRecursive(VIDEO_DIR);
      
      // Content-token access: list allowed videos, but do not burn usage on listing.
      if (ctx.kind === "contentToken") {
        const ti = ctx.tokenInfo || {};
        const allowed = Array.isArray(ti.allowedVideos) ? ti.allowedVideos.map(String) : [];
        const allowedSet = allowed.length > 0 ? new Set(allowed) : null;
        const filteredVideos = allowedSet ? videos.filter((v) => allowedSet.has(v.path)) : videos;
        const list = filteredVideos.map((v) => ({ ...v, unlocked: true }));
        const maxUses = Math.max(1, Math.floor(Number(ti.maxUses || 0)));
        const usesField = Math.max(0, Math.floor(Number(ti.currentUses || 0)));
        const usedLen = Array.isArray(ti.usedVideos) ? ti.usedVideos.length : 0;
        const uses = Math.max(usesField, usedLen);
        return json(res, 200, {
          ok: true,
          count: list.length,
          videos: list,
          user: {
            role: "token-user",
            quota: -1,
            unlockedCount: -1,
            token: {
              id: String(ti.id || ""),
              name: String(ti.name || "token"),
              maxUses,
              currentUses: uses,
              validUntil: ti.validUntil || undefined,
              bundleType: ti.bundleType || undefined,
            },
          },
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

    // API endpoint to manage content tokens
    if (pathname === "/api/content-tokens" && req.method === "GET") {
      const ctx = authContext(req, url);
      if (!ctx || ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
      if (ctx.user.role !== "admin") return json(res, 403, { ok: false, error: "forbidden" });
      
      const tokens = Array.isArray(ctx.user.contentTokens) ? ctx.user.contentTokens : [];
      return json(res, 200, {
        ok: true,
        contentTokens: tokens.map((t) => {
          const maxUses = Math.max(1, Math.floor(Number(t && t.maxUses || 0)));
          const usedVideos = Array.isArray(t && t.usedVideos) ? t.usedVideos : [];
          const currentField = Math.max(0, Math.floor(Number(t && t.currentUses || 0)));
          const currentUses = Math.max(currentField, usedVideos.length);
          return {
            ...t,
            maxUses,
            currentUses,
            usedVideos,
            priceZar: normalizeMoneyZar(t && t.priceZar),
          };
        }),
      });
    }

    // API endpoint to create content tokens
    if (pathname === "/api/content-tokens" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx || ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
      if (ctx.user.role !== "admin") return json(res, 403, { ok: false, error: "forbidden" });
      
      const body = await readJson(req).catch(() => null);
      const { name, maxUses, validUntil, allowedVideos, bundleType, priceZar } = body || {};
      
      // If bundleType is specified, create a bundle instead of using allowedVideos
      let finalAllowedVideos = allowedVideos;
      if (bundleType) {
        const allVideos = await listVideosRecursive(VIDEO_DIR);
        const bundleResult = await createBundleVideos(allVideos, bundleType);
        finalAllowedVideos = bundleResult.videos;
      }
      
      if (!name || typeof maxUses !== 'number' || maxUses <= 0) {
        return json(res, 400, { ok: false, error: "bad_request", message: "name and positive maxUses required" });
      }
      
      const tokenData = makeContentToken(ctx.user.id, name, maxUses, validUntil, finalAllowedVideos, bundleType);
      
      if (!ctx.user.contentTokens) {
        ctx.user.contentTokens = [];
      }
      
      ctx.user.contentTokens.push({
        id: tokenData.tokenId,
        token: tokenData.token,
        name: tokenData.name,
        maxUses: tokenData.maxUses,
        currentUses: 0,
        usedVideos: [],
        validUntil: tokenData.validUntil,
        allowedVideos: tokenData.allowedVideos,
        bundleType: tokenData.bundleType,
        priceZar: normalizeMoneyZar(priceZar),
        createdAt: new Date().toISOString()
      });
      
      await queueSaveUsers();
      
      return json(res, 200, {
        ok: true,
        token: tokenData.token,
        tokenId: tokenData.tokenId,
        name: tokenData.name,
        maxUses: tokenData.maxUses,
        validUntil: tokenData.validUntil,
        allowedVideos: tokenData.allowedVideos,
        bundleType: tokenData.bundleType,
        priceZar: normalizeMoneyZar(priceZar),
      });
    }

    // API endpoint to get available bundles
    if (pathname === "/api/bundles" && req.method === "GET") {
      const ctx = authContext(req, url);
      if (!ctx || ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
      if (ctx.user.role !== "admin") return json(res, 403, { ok: false, error: "forbidden" });
      
      const videos = await listVideosRecursive(VIDEO_DIR);
      
      // Calculate stats for each bundle type
      const bundleStats = {};
      const bundleTypes = ['10min', '15min', '30min', '45min', '1hour'];
      
      for (const bundleType of bundleTypes) {
        try {
          const bundle = await createBundleVideos(videos, bundleType);
          bundleStats[bundleType] = {
            videoCount: bundle.videos.length,
            totalDuration: bundle.totalDuration,
            targetDuration: bundle.targetDuration
          };
        } catch (e) {
          bundleStats[bundleType] = { error: e.message };
        }
      }
      
      return json(res, 200, {
        ok: true,
        bundles: bundleStats
      });
    }

    // API endpoint to delete content tokens
    if (pathname === "/api/content-tokens/delete" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx || ctx.kind !== "user") return json(res, 401, { ok: false, error: "unauthorized" });
      if (ctx.user.role !== "admin") return json(res, 403, { ok: false, error: "forbidden" });
      
      const body = await readJson(req).catch(() => null);
      const { tokenId } = body || {};
      
      if (!tokenId) {
        return json(res, 400, { ok: false, error: "bad_request", message: "tokenId required" });
      }
      
      const tokens = ctx.user.contentTokens || [];
      const index = tokens.findIndex(t => t.id === tokenId);
      
      if (index === -1) {
        return json(res, 404, { ok: false, error: "not_found" });
      }
      
      tokens.splice(index, 1);
      await queueSaveUsers();
      
      return json(res, 200, { ok: true });
    }

    if (pathname === "/api/admin/users") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });
      const users = usersDb.users
        .map((u) => {
          const loy = loyaltyForUser(u);
          return {
            username: u.username,
            role: u.role,
            quota: u.quota,
            unlockedCount: Array.isArray(u.unlocked) ? u.unlocked.length : 0,
            createdAt: u.createdAt,
            contentTokens: Array.isArray(u.contentTokens) ? u.contentTokens.length : 0,
            spentZar: loy.spentZar,
            points: loy.points,
            tier: loy.tier ? { id: loy.tier.id, name: loy.tier.name, discountPct: loy.tier.discountPct } : null,
          };
        })
        .sort((a, b) => a.username.localeCompare(b.username));
      return json(res, 200, { ok: true, users });
    }

    if (pathname === "/api/admin/set-loyalty" && req.method === "POST") {
      const ctx = authContext(req, url);
      if (!ctx) return json(res, 401, { ok: false, error: "unauthorized" });
      if (!(ctx.kind === "legacy" || ctx.role === "admin")) return json(res, 403, { ok: false, error: "forbidden" });
      const body = await readJson(req).catch(() => null);
      const username = cleanUsername(body && body.username);
      const spentZarRaw = body && body.spentZar;
      const pointsRaw = body && body.points;
      const hasSpent = spentZarRaw !== undefined && spentZarRaw !== null && spentZarRaw !== "";
      const hasPoints = pointsRaw !== undefined && pointsRaw !== null && pointsRaw !== "";
      if (!username || (!hasSpent && !hasPoints)) return json(res, 400, { ok: false, error: "bad_request" });

      const user = usersDb.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
      if (!user) return json(res, 404, { ok: false, error: "not_found" });

      if (hasSpent) {
        const spent = normalizeMoneyZar(spentZarRaw);
        user.spentZar = spent;
      }
      if (hasPoints) {
        const pts = Math.max(0, Math.floor(Number(pointsRaw)));
        if (!Number.isFinite(pts) || pts > 1_000_000_000) return json(res, 400, { ok: false, error: "bad_request" });
        user.points = pts;
      }

      await queueSaveUsers();
      return json(res, 200, { ok: true });
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
      if (ctx.kind === "contentToken" && !tokenAllowsVideo(ctx.tokenInfo, relDecoded)) {
        return text(res, 403, "forbidden\n");
      }
      const thumb = await ensureThumb(abs, relDecoded);
      const buf = await fsp.readFile(thumb);
      res.writeHead(200, {
        "Content-Type": "image/jpeg",
        "Content-Length": buf.length,
        "Cache-Control": "no-store",
        // Anti-piracy headers
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Cross-Origin-Resource-Policy": "same-site"
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
      if (ctx.kind === "contentToken" && !tokenAllowsVideo(ctx.tokenInfo, relDecoded)) {
        return text(res, 403, "forbidden\n");
      }
      const prev = await ensurePreview(abs, relDecoded);
      return serveFile(req, res, prev, { contentType: "video/mp4" });
    }

    if (pathname.startsWith("/media/") || pathname.startsWith("/download/")) {
      const isDownload = pathname.startsWith("/download/");
      const ctx = authContext(req, url);
      if (!ctx) return text(res, 401, "unauthorized\n");

      const rel = pathname.slice(isDownload ? "/download/".length : "/media/".length);
      let abs;
      let relDecoded;
      try {
        ({ abs, relDecoded } = await resolveVideoFromUrlPath(rel));
      } catch (err) {
        return text(res, 400, `${err.message}\n`);
      }

      if (ctx.kind === "contentToken") {
        if (!tokenAllowsVideo(ctx.tokenInfo, relDecoded)) {
          return text(res, 403, "forbidden\n");
        }
        // Only count a "use" the first time a given video is accessed by this token.
        if (req.method !== "HEAD") {
          const r = await consumeTokenVideoUse(ctx.user, ctx.tokenInfo, relDecoded);
          if (!r.ok) {
            return text(res, 403, r.error === "token_exhausted" ? "token_exhausted\n" : "forbidden\n");
          }
        }
      }
      // Legacy token or admin user can access everything.
      else if (!(ctx.kind === "legacy" || ctx.role === "admin")) {
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

// Add connection handling for stability
server.on('connection', (socket) => {
  // Set socket timeouts to prevent hanging connections
  socket.setTimeout(120000); // 2 minutes timeout
  socket.on('timeout', () => {
    console.log('Connection timed out');
    socket.destroy();
  });
  
  // Improve connection handling
  socket.setNoDelay(true);  // Reduce latency
  socket.setKeepAlive(true, 60000); // 1 minute keep-alive
});

// Add error handling for the server
server.on('error', (err) => {
  console.error('Server error:', err);
});

server.listen(PORT, HOST, () => {
  console.log(`Camfordick server running`);
  console.log(`VIDEO_DIR: ${VIDEO_DIR}`);
  for (const u of localUrls(PORT)) console.log(`  ${u}`);
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('Received SIGTERM, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
  });
});

process.on('SIGINT', () => {
  console.log('Received SIGINT, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
  });
});
