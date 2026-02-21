/**
 * Remote smoke test — verifies a deployed instance is healthy.
 *
 * Usage:
 *   SMOKE_URL=https://my-app.up.railway.app npm run smoke:remote
 *   node scripts/smoke-remote.js https://my-app.up.railway.app
 */

const TIMEOUT_MS = 30_000;

const PAIRING_PATTERNS = [
  "pairing required",
  "device token",
  "token_missing",
  "unauthorized",
];

const url = (process.env.SMOKE_URL || process.argv[2] || "").replace(/\/+$/, "");
if (!url) {
  console.error("Usage: SMOKE_URL=<base-url> node scripts/smoke-remote.js");
  process.exit(1);
}

const ac = new AbortController();
const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);

let step = 0;
const total = 3;

function pass(msg) {
  step++;
  console.log(`[${step}/${total}] PASS  ${msg}`);
}

function fail(msg) {
  step++;
  console.error(`[${step}/${total}] FAIL  ${msg}`);
  clearTimeout(timer);
  process.exit(1);
}

async function run() {
  // --- 1. Health check ---------------------------------------------------
  try {
    const res = await fetch(`${url}/setup/healthz`, { signal: ac.signal });
    if (res.status !== 200) fail(`/setup/healthz returned ${res.status}`);
    const body = await res.json();
    if (!body.ok) fail(`/setup/healthz body.ok is falsy: ${JSON.stringify(body)}`);
    pass("/setup/healthz → 200 { ok: true }");
  } catch (err) {
    fail(`/setup/healthz fetch error: ${err.message}`);
  }

  // --- 2. Gateway HTTP proxy ---------------------------------------------
  try {
    const res = await fetch(`${url}/openclaw`, {
      signal: ac.signal,
      redirect: "follow",
    });
    if (res.status !== 200) fail(`/openclaw returned ${res.status}`);
    const html = await res.text();
    if (html.length < 100) fail(`/openclaw body too short (${html.length} bytes)`);
    pass(`/openclaw → 200 HTML (${html.length} bytes)`);
  } catch (err) {
    fail(`/openclaw fetch error: ${err.message}`);
  }

  // --- 3. WebSocket connection -------------------------------------------
  const wsUrl = url.replace(/^http/, "ws") + "/openclaw";
  await new Promise((resolve) => {
    const holdMs = 3_000;
    let opened = false;

    const ws = new WebSocket(wsUrl);

    const wsTimer = setTimeout(() => {
      if (opened) {
        pass(`WebSocket held open for ${holdMs}ms`);
        ws.close(1000);
        resolve();
      } else {
        fail(`WebSocket did not open within ${holdMs}ms`);
      }
    }, holdMs);

    ws.addEventListener("open", () => {
      opened = true;
    });

    ws.addEventListener("close", (e) => {
      clearTimeout(wsTimer);
      if (opened && e.code === 1000) return; // our own graceful close

      const reason = (e.reason || "").toLowerCase();
      const isPairing = e.code === 1008 ||
        PAIRING_PATTERNS.some((p) => reason.includes(p));

      if (isPairing) {
        fail(`WebSocket rejected (pairing/auth): code=${e.code} reason="${e.reason}"`);
      } else {
        fail(`WebSocket closed unexpectedly: code=${e.code} reason="${e.reason}"`);
      }
    });

    ws.addEventListener("error", (err) => {
      clearTimeout(wsTimer);
      if (!opened) fail(`WebSocket connection error: ${err.message || "unknown"}`);
    });
  });

  clearTimeout(timer);
  console.log("\nAll checks passed.");
}

run().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(1);
});
