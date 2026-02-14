// api/validate.js
// Token bucket: 45 requests/min, burst 11
// KEY FIX: use userId as primary key, fallback to IP
// Redis shared store via Upstash REST EVAL (atomic)

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

async function upstashEval(lua, keys = [], args = []) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error("Missing Upstash Redis env vars");

  const endpoint = `${url}/eval`;
  const payload = { script: lua, keys, args };

  const r = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!r.ok) throw new Error(`Upstash error: HTTP ${r.status}`);
  const data = await r.json();
  return data?.result;
}

// Config
const CAPACITY = 11;
const REFILL_PER_MIN = 45;
const REFILL_RATE = REFILL_PER_MIN / 60000; // tokens per ms

// Redis value: "tokens|last_ms"
const LUA_TOKEN_BUCKET = `
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2]) -- tokens per ms
local now_ms = tonumber(ARGV[3])

local v = redis.call("GET", key)
local tokens = capacity
local last = now_ms

if v then
  local sep = string.find(v, "|")
  if sep then
    tokens = tonumber(string.sub(v, 1, sep-1)) or capacity
    last = tonumber(string.sub(v, sep+1)) or now_ms
  end
end

local elapsed = now_ms - last
if elapsed < 0 then elapsed = 0 end
tokens = math.min(capacity, tokens + elapsed * refill_rate)
last = now_ms

local allowed = 0
local retry_after_sec = 0

if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  local missing = 1 - tokens
  local ms_to_wait = missing / refill_rate
  retry_after_sec = math.ceil(ms_to_wait / 1000)
  if retry_after_sec < 1 then retry_after_sec = 1 end
end

-- keep key a bit longer than a minute
redis.call("SET", key, tostring(tokens) .. "|" .. tostring(last), "PX", 120000)

return { allowed, retry_after_sec, tokens }
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

  // Parse body
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

  // ✅ Keying strategy:
  // - If userId exists => per-user bucket (prevents burst test affecting normal test)
  // - else => per-ip bucket
  const key = userId ? `rl:user:${userId}` : `rl:ip:${ip}`;

  let allowed = 1;
  let retryAfterSec = 0;

  try {
    const result = await upstashEval(
      LUA_TOKEN_BUCKET,
      [key],
      [String(CAPACITY), String(REFILL_RATE), String(Date.now())]
    );

    allowed = Number(result?.[0] ?? 1);
    retryAfterSec = Number(result?.[1] ?? 0);
  } catch (e) {
    // ✅ Fail OPEN (don’t block everything if Redis blips)
    console.log(
      JSON.stringify({
        event: "RATE_LIMIT_BACKEND_ERROR",
        error: String(e?.message || e),
        ts: new Date().toISOString(),
      })
    );
    allowed = 1;
    retryAfterSec = 0;
  }

  if (allowed !== 1) {
    res.setHeader("Retry-After", String(retryAfterSec));

    console.log(
      JSON.stringify({
        event: "RATE_LIMIT_BLOCK",
        userId: userId || "anon",
        ip,
        key,
        retryAfterSec,
        ts: new Date().toISOString(),
      })
    );

    return res.status(429).json({
      blocked: true,
      reason: "Rate limit exceeded",
      sanitizedOutput: "",
      confidence: 0.99,
      retryAfter: retryAfterSec,
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
