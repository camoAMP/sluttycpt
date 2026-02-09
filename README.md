# SluttyCPT (Camodick video server)

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

## One Command (Server + Tunnel)

If you already created a named tunnel `camodick` in Cloudflare, you can start everything with:

```bash
bash scripts/run-public.sh
```

If your tunnel is in a different Cloudflare account than your current `cloudflared` login (common when you have multiple accounts/zones), you can run using a **tunnel token** (copy it from Cloudflare Zero Trust -> Networks -> Tunnels -> your tunnel):

```bash
TUNNEL_TOKEN="paste-your-tunnel-token-here" bash scripts/run-public.sh
```

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

## Troubleshooting

- `error code: 1033` on your domain:
  - Your hostname is routed to a Cloudflare Tunnel, but Cloudflare can’t see a connector online for that tunnel.
  - Fix: make sure your server is running (`curl http://127.0.0.1:5173/api/info`), then run the tunnel **from the same Cloudflare account that owns the domain**, using either:
    - The exact `cloudflared tunnel run --token ... --url http://127.0.0.1:5173` command shown in the Zero Trust dashboard, or
    - `cloudflared tunnel login` (pick the correct domain), then `cloudflared tunnel run <tunnel-name>`.
- `A DNS record managed by Workers already exists on that host`:
  - You have a Workers/Pages custom domain or a `Worker` DNS record on that hostname. Remove it (or use a different hostname) before routing the hostname to a Tunnel.
- `EADDRINUSE: address already in use 0.0.0.0:5173`:
  - Something is already using port `5173`. Stop it, or run with a new port:
    - `PORT=5174 bash scripts/run-public.sh`

## Admin Login

- Admin login URL: `/admin` (example: `https://videos.cptcommunityadults.fun/admin`)
- Sign-up is on `/` (the first account created becomes admin)
- User sign-in/sign-up is **email + password**

## Accounts + Quotas

- Users can **Sign Up / Sign In** in the UI.
- The **first** account created becomes **admin**.
- Admin can set a **quota (videos)** for each user.
- Locked videos show **thumbnails** and a **10s preview**; users must **unlock** to watch/download full.
- Admin can see **online sessions/devices** and use the built-in **chat** to message users.

## Buy Button (Optional)

If you want a simple "Buy Access" button on the landing page (no built-in payments, just a link):

```bash
export BUY_URL="https://cptcommunityadults.fun/"   # or your checkout/contact page
```

Restart the server after changing env vars.

## Encrypted Downloads (Offline Playback)

- When a video is unlocked, the player shows **Download Encrypted**.
- Encrypted downloads save a `.cptv` file that can only be played inside this app on the same device/browser profile.
- Use the **Offline** button to open and play a `.cptv` file.

Limitations: this discourages sharing but cannot prevent screen recording.

## Email Verification + Choose Username (Recommended)

When SMTP is configured, sign-up requires **email verification**:

1. User enters **Email + Password** and clicks **Sign Up**
2. Server emails a verification link
3. After clicking the link, the UI signs the user in and prompts them to **choose a username**

Server environment variables:

```bash
# Enable/disable verification (default: enabled when SMTP is configured)
export EMAIL_VERIFY=1

# Verification link TTL (minutes). Default: 1440 (24h)
export EMAIL_VERIFY_TTL_MIN=1440

# SMTP (required to send verification emails)
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="you@gmail.com"
export SMTP_PASS="your-app-password"
export MAIL_FROM="you@gmail.com"   # optional (defaults to SMTP_USER)

# Optional: override the external base URL used in email links
# (useful if the server sees http internally but users should open https)
# export PUBLIC_BASE_URL="https://videos.cptcommunityadults.fun"

# Optional: allow returning to a different UI origin (e.g. GitHub Pages)
# export ALLOWED_RETURN_ORIGINS="https://youruser.github.io"
```

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

## Video Bundles (New Feature)

The system now supports creating video bundles with predefined durations:

- **10 Minutes Bundle**: A curated collection of videos totaling approximately 10 minutes
- **15 Minutes Bundle**: A curated collection of videos totaling approximately 15 minutes
- **30 Minutes Bundle**: A curated collection of videos totaling approximately 30 minutes
- **45 Minutes Bundle**: A curated collection of videos totaling approximately 45 minutes
- **1 Hour Bundle**: A curated collection of videos totaling approximately 1 hour

### Creating Bundled Content Access Tokens

1. When creating a token, select one of the predefined bundle types from the dropdown
2. The system will automatically curate videos that fit within the duration constraints
3. The token will provide access to only the videos in that bundle
4. The bundle statistics (number of videos and total duration) are displayed in the admin panel

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
