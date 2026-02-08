# Camfordick (aka camodick)

Static web UI (GitHub Pages) + your PC serves the actual video files (not stored in git).

## What People Open

- GitHub Pages URL (the UI)
- The UI connects to your PC server over HTTPS (via a tunnel) to list/stream videos

## Run The PC Video Server

Videos live in `./videos` by default.

```bash
cd /home/camo/Phone/DCIM/Camera/local-video-streamer
mkdir -p videos

# Optional but recommended: require a token for /api/videos and /media/*
export TOKEN="change-me-to-a-long-random-string"

node server.js
```

The server prints local URLs. For remote viewers you need an HTTPS public URL (next section).

## Make It Reachable From The Internet (HTTPS)

GitHub Pages is HTTPS, so your PC server must also be reachable via **HTTPS** (otherwise browsers block it).

Recommended: use a tunnel that gives an `https://...` URL.

Example (Cloudflare quick tunnel):

```bash
# Install cloudflared first, then:
cloudflared tunnel --url http://127.0.0.1:5173
```

It prints an `https://xxxx.trycloudflare.com` URL. Use that in the UI as the “PC Server URL”.

## GitHub Pages Setup

1. Push this repo to GitHub (at minimum: `index.html`, `server.js`, `.gitignore`).
2. In GitHub: Settings -> Pages -> “Deploy from a branch”
3. Select branch: `main` and folder: `/ (root)`
4. Your UI will be available at your GitHub Pages URL.

## Share Link

Open your GitHub Pages UI, paste:

- PC Server URL: `https://xxxx.trycloudflare.com`
- Token: your `TOKEN` (if set)

Click **Connect Server**, then **Copy Link** and share that URL to others.
