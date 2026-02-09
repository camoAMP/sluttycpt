#!/usr/bin/env node
"use strict";

const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "..");
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, ".camfordick-data"));
const USERS_FILE = path.join(DATA_DIR, "users.json");

const ADMIN_USER = String(process.env.ADMIN_USER || process.env.ADMIN_USERNAME || "").trim();
const ADMIN_PASS = String(process.env.ADMIN_PASS || process.env.ADMIN_PASSWORD || "");

function usage(msg) {
  if (msg) console.error(msg);
  console.error("Usage:");
  console.error("  ADMIN_USER='Camoflage' ADMIN_PASS='...' node scripts/bootstrap-admin.js");
  process.exit(1);
}

if (!ADMIN_USER) usage("Missing ADMIN_USER.");
if (!ADMIN_PASS) usage("Missing ADMIN_PASS.");

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

async function main() {
  const username = cleanUsername(ADMIN_USER);
  const password = normalizePassword(ADMIN_PASS);
  if (!username) usage("Invalid ADMIN_USER (3-32 chars, letters/digits/._- only).");
  if (!password) usage("Invalid ADMIN_PASS (min 8 chars).");

  await fsp.mkdir(DATA_DIR, { recursive: true, mode: 0o700 }).catch(() => {});

  /** @type {{users: any[]}} */
  let db = { users: [] };
  try {
    const raw = await fsp.readFile(USERS_FILE, "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && Array.isArray(parsed.users)) db = parsed;
  } catch {
    // ok
  }

  const now = new Date().toISOString();
  let u = db.users.find((x) => String(x && x.username) === username) || null;

  const salt = crypto.randomBytes(16);
  const derived = await scryptAsync(password, salt);

  if (!u) {
    u = {
      id: crypto.randomUUID(),
      username,
      role: "admin",
      salt: salt.toString("hex"),
      passHash: derived.toString("hex"),
      quota: -1,
      unlocked: [],
      contentTokens: [],
      disabled: false,
      accessUntilMs: null,
      createdAt: now,
    };
    db.users.push(u);
  } else {
    u.username = username;
    u.role = "admin";
    u.salt = salt.toString("hex");
    u.passHash = derived.toString("hex");
    if (typeof u.quota !== "number") u.quota = -1;
    if (!Array.isArray(u.unlocked)) u.unlocked = [];
    if (!Array.isArray(u.contentTokens)) u.contentTokens = [];
    u.disabled = false;
    u.accessUntilMs = null;
    if (!u.createdAt) u.createdAt = now;
  }

  const tmp = `${USERS_FILE}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(db, null, 2) + "\n", { mode: 0o600 });
  await fsp.rename(tmp, USERS_FILE);

  console.log(`Admin user ready: ${username}`);
  console.log(`Users file: ${USERS_FILE}`);
  console.log("Restart server.js to pick up changes if it is already running.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

