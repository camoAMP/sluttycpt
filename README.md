# Camfordick (aka camodick)

Static web UI (GitHub Pages) + your PC serves the actual video files (not stored in git).

## What People Open (Recommended)

- Your domain (example: `https://videos.cptcommunityadults.fun/` or `https://cptcommunityadults.fun/`)
- That domain is pointed at your running `server.js` via an HTTPS tunnel (Cloudflare Tunnel), so the UI auto-connects and users never need to type a "server URL".

## Alternate Setup (GitHub Pages UI)

- GitHub Pages URL (the UI)
- The UI connects to your PC server over HTTPS (via a tunnel) to list/stream videos

## Run The PC Video Server

Videos live in `./videos` by default.

```bash
cd camodick
mkdir -p videos

# Optional: legacy admin token (full access via ?token=...).
# Keep this private if you want per-user quotas to matter.
export TOKEN="change-me-to-a-long-random-string"

# Optional: disable public sign-ups after you create accounts
# export SIGNUP_ENABLED=0

node server.js
```

The server prints local URLs. For remote viewers you need an HTTPS public URL (next section).

## Use Your Own Domain (Cloudflare Tunnel)

If you want users to simply open your domain with no server setup UI:

1. Put your domain on Cloudflare (DNS).
2. Create a Cloudflare Tunnel that points to your local server `http://127.0.0.1:5173`.
3. Route the hostname (DNS) to that tunnel.

High level commands (run on the machine/container running `server.js`):

```bash
# One-time login to Cloudflare in your browser
cloudflared tunnel login

# Create a named tunnel (pick a name)
cloudflared tunnel create camodick

# Route your domain to that tunnel
# Use a subdomain to avoid replacing whatever is currently on the root domain.
cloudflared tunnel route dns camodick videos.cptcommunityadults.fun

# NOTE: If the command outputs a hostname like "...cptcommunityadults.fun.SOMETHING-ELSE",
# you're logged into the wrong Cloudflare account/zone. Login again with the account that
# actually manages `cptcommunityadults.fun` DNS.

# Run the tunnel (it forwards HTTPS -> your local server)
cloudflared tunnel run camodick
```

Once that’s active, users just open your domain and sign in.

## Accounts + Quotas

- Users can **Sign Up / Sign In** in the UI.
- The **first** account created becomes **admin**.
- Admin can set a **quota (videos)** for each user.
- Locked videos show **thumbnails** and a **10s preview**; users must **unlock** to watch/download full.

## Content Access Tokens (New Feature)

As an admin user, you can now create **content access tokens** for specific users or groups. Each token provides access to a designated set of videos with configurable limits:

- **Token Name**: A descriptive name for the token (e.g. "User 1", "Family Access", etc.)
- **Max Uses**: Number of times the token can be used before expiring
- **Valid Until**: Optional expiration date for the token
- **Allowed Videos**: Optionally restrict the token to specific videos (leave empty for access to all videos)

### Creating Content Access Tokens

1. Log in as an admin user
2. Navigate to the "Content Access Tokens" section in the admin panel
3. Fill in the token details (name, max uses, validity period)
4. Optionally select specific videos to grant access to
5. Click "Create Token" to generate a unique token

### Using Content Access Tokens

To share access with the token:
1. Copy the generated token URL
2. Distribute this URL to the intended recipients
3. The recipients can use this link to access the designated content without needing individual accounts

## Anti-Piracy Measures

The system includes several measures to prevent unauthorized content distribution:

- **Screen Recording Prevention**: Content Security Policy (CSP) headers prevent embedding videos in iframes on other sites
- **Direct Download Protection**: Videos can only be accessed through the application interface
- **Session Tracking**: All video access is logged server-side for monitoring
- **Time-Limited Access**: Content access tokens can be configured with expiration dates
- **Usage Limits**: Tokens have configurable usage limits that prevent unlimited access
- **User Agent Verification**: Server tracks user agents to detect unusual access patterns

## Make It Reachable From The Internet (HTTPS)

GitHub Pages is HTTPS, so your PC server must also be reachable via **HTTPS** (otherwise browsers block it).

Recommended: use a tunnel that gives an `https://...` URL.

Example (Cloudflare quick tunnel):

```bash
# Install cloudflared first, then:
cloudflared tunnel --url http://127.0.0.1:5173
```

It prints an `https://xxxx.trycloudflare.com` URL. Use that in the UI as the "PC Server URL".

## GitHub Pages Setup

1. Push this repo to GitHub (at minimum: `index.html`, `server.js`, `.gitignore`).
2. In GitHub: Settings -> Pages -> "Deploy from a branch"
3. Select branch: `main` and folder: `/ (root)`
4. Your UI will be available at your GitHub Pages URL.

## Share Link

Open your GitHub Pages UI, paste:

- PC Server URL: `https://xxxx.trycloudflare.com`
- Legacy Token: leave blank (recommended), unless you want legacy full-access links

Click **Connect Server**, then **Copy Link** and share that URL to others.
