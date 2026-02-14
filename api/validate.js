// api/validate.js
// Rate limiting: max 45 requests/minute, burst 11 (per second)
// Uses Upstash Redis so parallel requests still get blocked correctly.

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
const LIMIT_BURST_PER_SEC = 11;

// Atomic Lua: increments minute & second counters, sets TTLs, checks limits.
// Returns: { allowed(0/1), retry_after_sec, minuteCount, burstCount, blockedBy }
const LUA_FIXED_WINDOW_DUAL = `
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

-- If burst exceeded => block quickly
if b > burstLimit then
  return {0, retryBurstSec, m, b, "burst"}
end

-- If minute exceeded => block
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

  // Identity: prefer userId if provided, else IP.
  // This prevents one user’s burst from blocking other users.
  const ident = userId ? `user:${userId}` : `ip:${ip}`;

  // Fixed windows:
  const now = Date.now();
  const minuteWindow = Math.floor(now / 60000); // changes every minute
  const secondWindow = Math.floor(now / 1000);  // changes every second

  const minuteKey = `rl:${ident}:m:${minuteWindow}`;
  const burstKey  = `rl:${ident}:s:${secondWindow}`;

  // TTLs: keep keys just beyond their window
  const minuteTTLms = 70 * 1000; // 70s
  const burstTTLms  = 3 * 1000;  // 3s

  // Retry-After values:
  // - burst: 1s (next second window)
  // - minute: seconds until next minute boundary
  const secToNextMinute = Math.max(1, 60 - (new Date(now).getSeconds()));
  const retryBurstSec = 1;

  let allowed = 1;
  let retryAfterSec = 0;
  let blockedBy = "none";
  let minuteCount = 0;
  let burstCount = 0;

  try {
    const result = await upstashEval(
      LUA_FIXED_WINDOW_DUAL,
      [minuteKey, burstKey],
      [
        String(LIMIT_PER_MIN),
        String(LIMIT_BURST_PER_SEC),
        String(minuteTTLms),
        String(burstTTLms),
        String(secToNextMinute),
        String(retryBurstSec),
      ]
    );

    allowed = Number(result?.[0] ?? 1);
    retryAfterSec = Number(result?.[1] ?? 0);
    minuteCount = Number(result?.[2] ?? 0);
    burstCount = Number(result?.[3] ?? 0);
    blockedBy = String(result?.[4] ?? "none");
  } catch (e) {
    // Fail OPEN (don’t block normal usage due to Redis blip)
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
      reason: blockedBy === "burst" ? "Rate limit exceeded (burst)" : "Rate limit exceeded (per-minute)",
      sanitizedOutput: "",
      confidence: 0.99,
      retryAfter: retryAfterSec,
      blockedBy,
      user: userId || "anon",
      ip,
      latency: msSince(start),
    });
  }

  // Output sanitization (not the main focus here, but safe)
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
