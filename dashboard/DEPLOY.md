# KubeSentinel Dashboard – Cloudflare Deployment Guide

## Architecture

```
Browser → Cloudflare Pages (static dashboard)
               ↓ API calls (fetch)
         Cloudflare Tunnel (public HTTPS URL)
               ↓ tunnel (no open ports needed)
         Your machine: Flask :5000
               ↓ reads
         forensics/*.json (written by Go monitor)
```

## Step 1 — Deploy the Dashboard to Cloudflare Pages

### Option A: Direct Upload (fastest)

1. Go to [Cloudflare Pages](https://dash.cloudflare.com/?to=/:account/pages)
2. Click **Create a project** → **Direct Upload**
3. Name it `kubesentinel-dashboard`
4. Upload the entire `dashboard/` folder (index.html, style.css, app.js)
5. Done — you'll get a URL like `https://kubesentinel-dashboard.pages.dev`

### Option B: Git integration

1. Push the repo to GitHub
2. In Cloudflare Pages, connect to GitHub
3. Set:
   - **Build command**: (leave empty — static files)
   - **Build output directory**: `dashboard`
4. Deploy

## Step 2 — Expose Flask with Cloudflare Tunnel

### Install cloudflared

```bash
# Linux / macOS
brew install cloudflare/cloudflare/cloudflared
# or download from: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/

# Windows (winget)
winget install Cloudflare.cloudflared
```

### Quick tunnel (no account needed, ephemeral URL)

```bash
# Start your Flask server first
cd ai-module
python server.py

# In another terminal, create a quick tunnel
cloudflared tunnel --url http://localhost:5000
```

This gives you a URL like `https://random-name.trycloudflare.com`.

### Named tunnel (stable URL, recommended)

```bash
# 1. Login to Cloudflare
cloudflared tunnel login

# 2. Create a named tunnel
cloudflared tunnel create kubesentinel-api

# 3. Route DNS (if you have a domain)
cloudflared tunnel route dns kubesentinel-api api.yourdomain.com

# 4. Create config file (~/.cloudflared/config.yml)
cat > ~/.cloudflared/config.yml << 'EOF'
tunnel: kubesentinel-api
credentials-file: ~/.cloudflared/<TUNNEL_ID>.json

ingress:
  - hostname: api.yourdomain.com
    service: http://localhost:5000
  - service: http_status:404
EOF

# 5. Run the tunnel
cloudflared tunnel run kubesentinel-api
```

## Step 3 — Configure the Dashboard

1. Open your dashboard at `https://kubesentinel-dashboard.pages.dev`
2. Click **Settings** in the sidebar
3. Enter your tunnel URL:
   - Quick tunnel: `https://random-name.trycloudflare.com`
   - Named tunnel: `https://api.yourdomain.com`
4. Click **Save & Apply**
5. Click **Test Connection** to verify

## Step 4 — CORS (already configured)

The Flask server automatically accepts requests from:
- `*.pages.dev` (Cloudflare Pages)
- `*.trycloudflare.com` (quick tunnels)
- `localhost:3000/5000/8080` (local development)

To add custom origins:
```bash
export CORS_ALLOWED_ORIGINS="https://your-custom-domain.com,http://localhost:3000"
```

## Environment Variables Reference

Set these on the machine running Flask + Go monitor:

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ALLOWED_ORIGINS` | localhost:3000,5000,8080 | Comma-separated allowed origins |
| `ALLOW_UNAUTHENTICATED_API` | `false` | Set `true` for demo mode |
| `TRAINING_API_TOKEN` | (none) | Bearer token for API auth |
| `ENRICH_WITH_GEMINI` | `false` | Enable Gemini LLM enrichment |
| `GEMINI_API_KEY` | (none) | Google Gemini API key |
| `WARMUP_THRESHOLD` | `50` | Samples before IF starts scoring |

## Running Everything Together

```bash
# Terminal 1: Flask AI service
cd ai-module
export ALLOW_UNAUTHENTICATED_API=true
python server.py

# Terminal 2: Cloudflare Tunnel
cloudflared tunnel --url http://localhost:5000

# Terminal 3: Go runtime monitor (writes to forensics/)
./bin/kubesentinel monitor-webhook --port 8080 --ai-endpoint http://localhost:5000

# Terminal 4: (optional) Falco Sidekick → webhook
# Configure Sidekick to POST events to http://localhost:8080/events
```

## File Structure

```
dashboard/
├── index.html    ← Main SPA page
├── style.css     ← Design system
└── app.js        ← API polling + rendering logic
```

All three files are purely static — no build step, no bundler, no npm.
Deploy the entire `dashboard/` directory to Cloudflare Pages.
