#!/usr/bin/env node
"use strict";

const http = require("http");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const os = require("os");

const PORT = Number(process.env.PORT || 5173);
const HOST = process.env.HOST || "0.0.0.0";
const VIDEO_DIR = path.resolve(process.env.VIDEO_DIR || path.join(process.cwd(), "videos"));
const INDEX_FILE = path.resolve(process.cwd(), "index.html");
const TOKEN = String(process.env.TOKEN || "");

const VIDEO_EXTS = new Set([".mp4", ".webm", ".mkv", ".avi"]);

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
    default:
      return "application/octet-stream";
  }
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

async function serveMedia(req, res, relUrlPath) {
  let segments;
  try {
    segments = safeDecodeSegments(relUrlPath);
  } catch {
    return text(res, 400, "Bad media path\n");
  }

  const relFsPath = path.join(...segments);
  const abs = path.resolve(VIDEO_DIR, relFsPath);
  if (!insideBase(VIDEO_DIR, abs)) return text(res, 403, "Forbidden\n");

  let st;
  try {
    st = await fsp.stat(abs);
  } catch {
    return text(res, 404, "Not found\n");
  }
  if (!st.isFile()) return text(res, 404, "Not found\n");

  const ext = path.extname(abs).toLowerCase();
  const ct = contentTypeForExt(ext);
  const size = st.size;

  res.setHeader("Accept-Ranges", "bytes");
  res.setHeader("Content-Type", ct);
  res.setHeader("Cache-Control", "no-store");

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

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const { pathname } = url;

    // Basic CORS for API/media if someone hosts index.html elsewhere.
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Range,Content-Type");
    if (req.method === "OPTIONS") return res.end();

    if (pathname === "/" || pathname === "/index.html") return serveIndex(req, res);

    if (pathname === "/api/info") {
      return json(res, 200, {
        ok: true,
        mode: "server",
        videoDirName: path.basename(VIDEO_DIR),
        videoDir: VIDEO_DIR,
        exts: [...VIDEO_EXTS].map((e) => e.slice(1)),
        auth: TOKEN ? "token" : "none",
        now: new Date().toISOString(),
      });
    }

    if (pathname === "/api/videos") {
      if (TOKEN && url.searchParams.get("token") !== TOKEN) {
        return json(res, 401, { ok: false, error: "unauthorized" });
      }
      const videos = await listVideosRecursive(VIDEO_DIR);
      return json(res, 200, { ok: true, count: videos.length, videos });
    }

    if (pathname.startsWith("/media/")) {
      if (TOKEN && url.searchParams.get("token") !== TOKEN) {
        return text(res, 401, "unauthorized\n");
      }
      const rel = pathname.slice("/media/".length);
      return serveMedia(req, res, rel);
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
