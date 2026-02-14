// api/validate.js
// Rate limiting: max 45 requests/minute, burst 11 (using 5-second burst window)
// Uses Upstash Redis so parallel requests across instances still get blocked.

function nowMs() {
  return Date.now();
}
function msSince(start) {
  return Math.max(1, Date.now() - start);
}
function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) return xff.split(",")[0].trim();
  return req.socket?.remoteAddress || "unknown";
}

async function upstashEval(script, keys, args) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error("Missing Upstash Redis env vars");

  const r = await fetch(`${url}/eval`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ script, keys, args }),
  });

  if (!r.ok) throw new Error(`Upstash error: HTTP ${r.status}`);
  const data = await r.json();
  return data?.result;
}

// Limits
const LIMIT_PER_MIN = 45;
const LIMIT_BURST = 11;

// Burst window (key change): 5 seconds
const BURST_WINDOW_MS = 5000;

// Atomic Lua: increments minute & burst-window counters, sets TTLs, checks limits.
// Returns: [allowed(0/1), retry_after_sec, minuteCount, burstCount, blockedBy]
const LUA_DUAL_FIXED_WINDOW = `
local minuteKey = KEYS[1]
local burstKey  = KEYS[2]

local minuteLimit = tonumber(ARGV[1])
local burstLimit  = tonumber(ARGV[2])

local minuteTTLms = tonumber(ARGV[3])
local burstTTLms  = tonumber(ARGV[4])

local retryMinSec = tonumber(ARGV[5])
local retryBurstSec = tonumber(ARGV[6])

local m = redis.call("INCR", minuteKey)
if m == 1 then
  redis.call("PEXPIRE", minuteKey, minuteTTLms)
end

local b = redis.call("INCR", burstKey)
if b == 1 then
  redis.call("PEXPIRE", burstKey, burstTTLms)
end

if b > burstLimit then
  return {0, retryBurstSec, m, b, "burst"}
end

if m > minuteLimit then
  return {0, retryMinSec, m, b, "minute"}
end

return {1, 0, m, b, "none"}
`;

export default async function handler(req, res) {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  const start = nowMs();

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method !== "POST") {
    return res.status(405).json({
      blocked: true,
      reason: "Method not allowed",
      sanitizedOutput: "",
      confidence: 0.99,
      latency: msSince(start),
    });
  }

  // Parse body safely
  let body = {};
  try {
    body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body || {});
  } catch {
    return res.status(400).json({
      blocked: true,
      reason: "Invalid JSON body",
      sanitizedOutput: "",
      confidence: 0.95,
      latency: msSince(start),
    });
  }

  const userId = typeof body.userId === "string" ? body.userId.trim() : "";
  const input = typeof body.input === "string" ? body.input : "";
  const category = typeof body.category === "string" ? body.category : "";

  if (category !== "Rate Limiting") {
    return res.status(400).json({
      blocked: true,
      reason: "Invalid category",
      sanitizedOutput: "",
      confidence: 0.9,
      latency: msSince(start),
    });
  }

  const ip = getClientIp(req);

  // Identity: prefer userId if provided; else IP.
  const ident = userId ? `user:${userId}` : `ip:${ip}`;

  const now = Date.now();

  // Windows
  const minuteWindow = Math.floor(now / 60000);
  const burstWindow = Math.floor(now / BURST_WINDOW_MS);

  const minuteKey = `rl:${ident}:m:${minuteWindow}`;
  const burstKey = `rl:${ident}:b:${burstWindow}`;

  // TTLs: keep keys a bit longer than window to handle delays
  const minuteTTLms = 70 * 1000;
  const burstTTLms = BURST_WINDOW_MS + 2000;

  // Retry-after calculations
  const secToNextMinute = Math.max(1, 60 - new Date(now).getSeconds());

  const msIntoBurst = now % BURST_WINDOW_MS;
  const msToNextBurst = BURST_WINDOW_MS - msIntoBurst;
  const secToNextBurst = Math.max(1, Math.ceil(msToNextBurst / 1000));

  let allowed = 1;
  let retryAfterSec = 0;
  let blockedBy = "none";
  let minuteCount = 0;
  let burstCount = 0;

  try {
    const result = await upstashEval(
      LUA_DUAL_FIXED_WINDOW,
      [minuteKey, burstKey],
      [
        String(LIMIT_PER_MIN),
        String(LIMIT_BURST),
        String(minuteTTLms),
        String(burstTTLms),
        String(secToNextMinute),
        String(secToNextBurst),
      ]
    );

    allowed = Number(result?.[0] ?? 1);
    retryAfterSec = Number(result?.[1] ?? 0);
    minuteCount = Number(result?.[2] ?? 0);
    burstCount = Number(result?.[3] ?? 0);
    blockedBy = String(result?.[4] ?? "none");
  } catch (e) {
    // Fail OPEN (don't block normal usage if Redis has a hiccup)
    console.log(JSON.stringify({ event: "RATE_LIMIT_BACKEND_ERROR", error: String(e?.message || e) }));
    allowed = 1;
  }

  if (allowed !== 1) {
    res.setHeader("Retry-After", String(retryAfterSec));

    console.log(
      JSON.stringify({
        event: "RATE_LIMIT_BLOCK",
        ident,
        userId: userId || "anon",
        ip,
        blockedBy,
        retryAfterSec,
        minuteCount,
        burstCount,
        ts: new Date().toISOString(),
      })
    );

    return res.status(429).json({
      blocked: true,
      reason: blockedBy === "burst"
        ? "Rate limit exceeded (burst)"
        : "Rate limit exceeded (per-minute)",
      sanitizedOutput: "",
      confidence: 0.99,
      retryAfter: retryAfterSec,
      blockedBy,
      user: userId || "anon",
      ip,
      latency: msSince(start),
    });
  }

  const sanitizedOutput = input.replace(/[<>]/g, "");

  return res.status(200).json({
    blocked: false,
    reason: "Input passed all security checks",
    sanitizedOutput,
    confidence: 0.95,
    user: userId || "anon",
    ip,
    latency: msSince(start),
  });
}
