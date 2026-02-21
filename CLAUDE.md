# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a Railway deployment wrapper for **Openclaw** (an AI coding assistant platform). It provides:

- A web-based setup wizard at `/setup` (protected by `SETUP_PASSWORD`)
- Automatic reverse proxy from public URL → internal Openclaw gateway
- Persistent state via Railway Volume at `/data`
- One-click backup export of configuration and workspace

The wrapper manages the Openclaw lifecycle: onboarding → gateway startup → traffic proxying.

## Development Commands

```bash
# Local development (requires Openclaw in /openclaw or OPENCLAW_ENTRY set)
npm run dev

# Production start
npm start

# Syntax check
npm run lint

# Local smoke test (requires Docker)
npm run smoke
```

## Docker Build & Local Testing

```bash
# Build the container (builds Openclaw from source)
docker build -t openclaw-railway-template .

# Run locally with volume
docker run --rm -p 8080:8080 \
  -e PORT=8080 \
  -e SETUP_PASSWORD=test \
  -e OPENCLAW_STATE_DIR=/data/.openclaw \
  -e OPENCLAW_WORKSPACE_DIR=/data/workspace \
  -v $(pwd)/.tmpdata:/data \
  openclaw-railway-template

# Access setup wizard
open http://localhost:8080/setup  # password: test
```

## Architecture

### Request Flow

1. **User → Railway → Wrapper (Express on PORT)** → routes to:
   - `/setup/*` → setup wizard (auth: Basic with `SETUP_PASSWORD`)
   - All other routes → proxied to internal gateway

2. **Wrapper → Gateway** (localhost:18789 by default)
   - HTTP/WebSocket reverse proxy via `http-proxy`
   - Automatically injects `Authorization: Bearer <token>` header

### Lifecycle States

1. **Unconfigured**: No `openclaw.json` exists
   - All non-`/setup` routes redirect to `/setup`
   - User completes setup wizard → runs `openclaw onboard --non-interactive`

2. **Configured**: `openclaw.json` exists
   - Gateway starts eagerly at boot (not lazily on first request)
   - While gateway is starting, requests get a loading page (`loading.html`, auto-refreshes)
   - Once ready, proxies all traffic with injected bearer token

### Key Files

- **src/server.js** (main entry): Express wrapper, proxy setup, gateway lifecycle management, configuration persistence (server logic only - no inline HTML/CSS)
- **src/public/** (static assets for setup wizard):
  - **setup.html**: Setup wizard HTML structure
  - **styles.css**: Setup wizard styling (extracted from inline styles)
  - **setup-app.js**: Client-side JS for `/setup` wizard (vanilla JS, no build step)
  - **loading.html**: "Starting up" page shown while gateway is launching (auto-refreshes every 3s)
- **Dockerfile**: Multi-stage build (builds Openclaw from source, installs wrapper deps, runs as root)
- **railway.toml**: Railway deploy config (healthcheck path, start command)

### Environment Variables

**Required:**

- `SETUP_PASSWORD` — protects `/setup` wizard

**Recommended (Railway template defaults):**

- `OPENCLAW_STATE_DIR=/data/.openclaw` — config + credentials
- `OPENCLAW_WORKSPACE_DIR=/data/workspace` — agent workspace

**Optional:**

- `OPENCLAW_GATEWAY_TOKEN` — auth token for gateway (auto-generated if unset)
- `PORT` — wrapper HTTP port (default 8080)
- `INTERNAL_GATEWAY_PORT` — gateway internal port (default 18789)
- `OPENCLAW_ENTRY` — path to `entry.js` (default `/openclaw/dist/entry.js`)
- `OPENCLAW_TEMPLATE_DEBUG` — set to `true` to enable verbose token/proxy logging

### Authentication Flow

The wrapper manages a **two-layer auth scheme**:

1. **Setup wizard auth**: Basic auth with `SETUP_PASSWORD`, timing-safe comparison, rate-limited (50 req/min per IP)
2. **Gateway auth**: Bearer token with multi-source resolution and automatic sync
   - **Token resolution order** (src/server.js:31-69):
     1. `OPENCLAW_GATEWAY_TOKEN` env variable (highest priority)
     2. Persisted file at `${STATE_DIR}/gateway.token`
     3. Generate new random token and persist
   - **Token synchronization**: Written to `openclaw.json` via direct JSON file write during onboarding and on every gateway start
   - **Token injection**:
     - HTTP requests: via `proxy.on("proxyReq")` event handler
     - WebSocket upgrades: via `headers` option in `proxy.ws()`

### Onboarding Process

When the user runs setup (src/server.js:554-830):

1. Calls `openclaw onboard --non-interactive` with user-selected auth provider and `--gateway-token` flag
2. **Syncs wrapper token to `openclaw.json`** via direct JSON file write (overwrites whatever `onboard` generated):
   - Sets `gateway.auth.mode` to `"token"`, `gateway.auth.token` to `OPENCLAW_GATEWAY_TOKEN`
   - Sets `gateway.trustedProxies`, `gateway.controlUi.allowInsecureAuth`
3. Writes channel configs (Telegram/Discord/Slack/IRC) directly to `openclaw.json` via `openclaw config set --json`
4. Sets `plugins.autoEnable=false` for security
5. Restarts gateway process to apply all config changes
6. Waits for gateway readiness (polls multiple endpoints)

**Important**: Channel setup bypasses `openclaw channels add` and writes config directly because `channels add` is flaky across different Openclaw builds.

### Gateway Token Injection

The wrapper **always** injects the bearer token into proxied requests so browser clients don't need to know it:

- HTTP requests: via `proxy.on("proxyReq")` event handler
- WebSocket upgrades: via `headers` option in `proxy.ws()`

**Important**: Token injection uses `http-proxy` event handlers (`proxyReq`) and options-based headers (for WebSocket) rather than direct `req.headers` modification. Direct header modification does not reliably work with WebSocket upgrades.

This allows the Control UI at `/openclaw` to work without user authentication.

### Backup Export

`GET /setup/export` (src/server.js:896-943):

- Creates a `.tar.gz` archive of `STATE_DIR` and `WORKSPACE_DIR`
- Preserves relative structure under `/data` (e.g., `.openclaw/`, `workspace/`)
- Includes dotfiles (config, credentials, sessions)

## Common Development Tasks

### Testing the setup wizard

1. Delete `${STATE_DIR}/openclaw.json` (or run Reset in the UI)
2. Visit `/setup` and complete onboarding
3. Check logs for gateway startup and channel config writes

### Testing authentication

- Setup wizard: Clear browser auth, verify Basic auth challenge
- Gateway: Remove `Authorization` header injection and verify requests fail

### Debugging gateway startup

Check logs for:

- `[gateway] starting with command: ...` (src/server.js:214)
- `[gateway] ready at <endpoint>` (src/server.js:127)
- `[gateway] failed to become ready after 20000ms` (src/server.js:136)

If gateway doesn't start:

- Verify `openclaw.json` exists and is valid JSON
- Check `STATE_DIR` and `WORKSPACE_DIR` are writable
- Ensure bearer token is set in config (`gateway.auth.token`)

### Modifying onboarding args

Edit `buildOnboardArgs()` (src/server.js:552-619) to add new CLI flags or auth providers.

### Adding new channel types

1. Add channel-specific fields to `/setup` HTML (src/public/setup.html)
2. Add config-writing logic in `/setup/api/run` handler (src/server.js)
3. Update client JS to collect the fields (src/public/setup-app.js)

## Railway Deployment Notes

- Template must mount a volume at `/data`
- Must set `SETUP_PASSWORD` in Railway Variables
- Public networking must be enabled (assigns `*.up.railway.app` domain)
- Openclaw version is pinned via Docker build arg `OPENCLAW_GIT_REF` (default: `v2026.2.21`)

## Serena Semantic Coding

This project has been onboarded with **Serena** (semantic coding assistant via MCP). Comprehensive memory files are available covering:

- Project overview and architecture
- Tech stack and codebase structure
- Code style and conventions
- Development commands and task completion checklist
- Quirks and gotchas

**When working on tasks:**

1. Check `mcp__serena__check_onboarding_performed` first to see available memories
2. Read relevant memory files before diving into code (e.g., `mcp__serena__read_memory`)
3. Use Serena's semantic tools for efficient code exploration:
   - `get_symbols_overview` - Get high-level file structure without reading entire file
   - `find_symbol` - Find classes, functions, methods by name path
   - `find_referencing_symbols` - Understand dependencies and usage
4. Prefer symbolic editing (`replace_symbol_body`, `insert_after_symbol`) for precise modifications

This avoids repeatedly reading large files and provides instant context about the project.

## Quirks & Gotchas

1. **Gateway token must be stable across redeploys** → Always set `OPENCLAW_GATEWAY_TOKEN` env variable in Railway (highest priority); token is synced to `openclaw.json` via direct JSON file write during onboarding and on every gateway start. This is required because `openclaw onboard` generates its own random token and the gateway reads from config file.
2. **Channels are written via `config set --json`, not `channels add`** → avoids CLI version incompatibilities
3. **Gateway readiness check polls multiple endpoints** (`/openclaw`, `/`, `/health`) → some builds only expose certain routes (src/server.js:119)
4. **Discord bots require MESSAGE CONTENT INTENT** → documented in setup wizard (src/public/setup.html)
5. **Gateway spawn inherits stdio** → logs appear in wrapper output (src/server.js:206)
6. **WebSocket auth requires proxy event handlers** → Direct `req.headers` modification doesn't work for WebSocket upgrades with http-proxy; must use `headers` option in `proxy.ws()` to reliably inject Authorization header
7. **Control UI requires allowInsecureAuth + trustedProxies** → `gateway.controlUi.allowInsecureAuth=true` and `gateway.trustedProxies=["127.0.0.1","::1"]` are set during onboarding AND re-applied on every gateway start via direct JSON file write (not `config set` CLI, which doesn't handle nested keys reliably). v2026.2.21+ rejects proxy headers from untrusted addresses, causing "disconnected (1008): pairing required" errors. **Do NOT use `trusted-proxy` auth mode** — it has a known unmerged bug (PR #17705) where the device-pairing layer doesn't recognize it as valid auth, causing permanent "pairing required" WebSocket rejections.
8. **Gateway `--allow-unconfigured` flag** → Added to gateway spawn args to support latest openclaw builds that require explicit opt-in for unconfigured state. Ignored by older builds.
9. **Discord `dm` key renamed to `direct`** → Latest openclaw renamed the session key from `dm` to `direct` (with backward compat layer). Wrapper uses `direct` for forward compatibility.
10. **Supported auth providers** → OpenAI, Anthropic, Chutes (OAuth), vLLM (OAuth), Google, OpenRouter, Vercel AI Gateway, Moonshot AI (Kimi K2.5), Z.AI (multiple endpoint variants), MiniMax (M2.5 + OAuth + CN endpoint), Qwen, Copilot, Synthetic, OpenCode Zen, LiteLLM, xAI (Grok), Qianfan, Xiaomi, Venice AI, Together AI, Hugging Face, Cloudflare AI Gateway, Custom Provider, Volcano Engine (Doubao), BytePlus. Flag mappings in `buildOnboardArgs()`.
11. **IRC channel support** → Setup wizard supports IRC server/nick/channels/password configuration via `config set --json channels.irc`.
12. **Feishu/Lark moved to community plugin** → No longer built-in; users must install `clawdbot-feishu` from the plugin registry.
13. **DO NOT use `USER node` in Dockerfile** → Railway 볼륨(`/data`)은 root 소유이며, non-root 사용자로 전환하면 기존 config/data 파일 접근 불가. `entrypoint.sh`의 `chown` 우회도 실패함. Railway 컨테이너는 격리 환경이므로 root 실행 유지.
14. **Token logging is debug-only** → Full token values are only logged when `OPENCLAW_TEMPLATE_DEBUG=true`. Production logs show only first 16 chars.
15. **Plugin auto-enable disabled** → `plugins.autoEnable` set to `false` during onboarding for security.
16. **Railway 대시보드 Start Command가 최우선** → 대시보드 Settings → Deploy의 Custom Start Command가 `railway.toml`의 `startCommand`와 Dockerfile `CMD`보다 우선함. 배포 실패 시 코드를 의심하기 전에 대시보드 설정부터 확인할 것.
17. **Setup auth uses timing-safe comparison** → Password checked via `crypto.timingSafeEqual` on SHA-256 hashes to prevent timing attacks. Rate-limited at 50 requests/min per IP with in-memory tracker.
18. **Gateway starts eagerly at boot** → `ensureGatewayRunning()` is called in the `listen` callback when configured. Requests arriving before gateway is ready get `loading.html` (auto-refresh 3s) instead of a 503 error.
19. **Hooks sessionKey override rejected** → `POST /hooks/agent` now rejects payload `sessionKey` overrides by default (v2026.2.12 breaking change). Callers must omit `sessionKey` or use the server-assigned value.
20. **Cloudflare AI Gateway requires extra IDs** → In addition to the API key, Cloudflare requires `--cloudflare-ai-gateway-account-id` and `--cloudflare-ai-gateway-gateway-id`. The setup wizard only supports the API key field; users must set account/gateway IDs via environment variables or post-setup `config set`.
21. **Custom Provider support** → v2026.2.15 added `custom-api-key` auth choice with `--custom-base-url`, `--custom-model-id`, `--custom-provider-id`, and `--custom-compatibility` (openai/anthropic) flags. The setup wizard shows extra fields when Custom Provider is selected.
22. **Skill-enabling binaries in container** → `gh` (GitHub CLI), `ffmpeg`, `tmux` installed in the runtime image to unlock `github`, `video-frames`, `tmux` skills respectively. Skills also depend on env vars (`GEMINI_API_KEY`, `NOTION_API_KEY`, `OPENAI_API_KEY`, etc.) and tool policy settings.
23. **Optional Chromium pre-install** → Build with `--build-arg OPENCLAW_INSTALL_BROWSER=true` to pre-install Chromium + Xvfb (~300MB) into the image. Avoids the 60-90s runtime Playwright install on first browser skill use. Disabled by default to keep image size small.
24. **Hooks token must differ from gateway token** → v2026.2.21+ refuses to start if `hooks.token` matches `gateway.auth.token` (GHSA-76m6-pj3w-v7mf). The wrapper checks for and fixes collisions during onboarding and on every gateway start.
