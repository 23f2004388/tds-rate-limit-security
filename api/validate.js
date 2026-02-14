// Rate limiting: 45 requests/minute, burst 11
// Token bucket per userId + IP (best-effort on serverless)

function nowMs() {
  return Date.now();
}

function getClientIp(req) {
  // Vercel/Proxies often set x-forwarded-for
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) return xff.split(",")[0].trim();
  return req.socket?.remoteAddress || "unknown";
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// Global in-memory store (best-effort; serverless may cold start)
function getStore() {
  if (!globalThis.__RATE_LIMIT_STORE__) {
    globalThis.__RATE_LIMIT_STORE__ = new Map();
  }
  return globalThis.__RATE_LIMIT_STORE__;
}

// Token bucket parameters
const CAPACITY = 11;          // burst
const REFILL_PER_MIN = 45;    // tokens per minute
const REFILL_PER_MS = REFILL_PER_MIN / 60000; // tokens per ms

function getBucketKey(userId, ip) {
  return `${userId || "anon"}::${ip || "unknown"}`;
}

function takeToken(bucket) {
  const t = nowMs();
  const elapsed = t - bucket.lastRefill;

  // Refill tokens
  bucket.tokens = Math.min(CAPACITY, bucket.tokens + elapsed * REFILL_PER_MS);
  bucket.lastRefill = t;

  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    return { allowed: true, retryAfterSec: 0 };
  }

  // Compute retry-after until 1 token
  const missing = 1 - bucket.tokens; // between (0,1]
  const msToWait = missing / REFILL_PER_MS;
  const retryAfterSec = Math.max(1, Math.ceil(msToWait / 1000));
  return { allowed: false, retryAfterSec };
}

export default async function handler(req, res) {
  // CORS (safe)
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") return res.status(200).end();

  const start = nowMs();

  if (req.method !== "POST") {
    return res.status(405).json({
      blocked: true,
      reason: "Method not allowed",
      sanitizedOutput: "",
      confidence: 0.99,
      latency: Math.max(1, nowMs() - start),
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
      latency: Math.max(1, nowMs() - start),
    });
  }

  const userId = typeof body.userId === "string" ? body.userId : "";
  const input = typeof body.input === "string" ? body.input : "";
  const category = typeof body.category === "string" ? body.category : "";

  if (category !== "Rate Limiting") {
    return res.status(400).json({
      blocked: true,
      reason: "Invalid category",
      sanitizedOutput: "",
      confidence: 0.9,
      latency: Math.max(1, nowMs() - start),
    });
  }

  // Identify client
  const ip = getClientIp(req);
  const key = getBucketKey(userId, ip);

  const store = getStore();
  let bucket = store.get(key);
  if (!bucket) {
    bucket = { tokens: CAPACITY, lastRefill: nowMs(), createdAt: nowMs() };
    store.set(key, bucket);
  }

  const decision = takeToken(bucket);

  if (!decision.allowed) {
    // Required: 429 + Retry-After header
    res.setHeader("Retry-After", String(decision.retryAfterSec));

    // Log security event (monitoring)
    console.log(
      JSON.stringify({
        event: "RATE_LIMIT_BLOCK",
        userId: userId || "anon",
        ip,
        key,
        retryAfterSec: decision.retryAfterSec,
        ts: new Date().toISOString(),
      })
    );

    return res.status(429).json({
      blocked: true,
      reason: "Rate limit exceeded",
      sanitizedOutput: "",
      confidence: 0.99,
      retryAfter: decision.retryAfterSec,
      user: userId || "anon",
      ip,
      latency: Math.max(1, nowMs() - start),
    });
  }

  // Sanitization not applicable here (still return something safe)
  const sanitizedOutput = input.replace(/[<>]/g, "");

  return res.status(200).json({
    blocked: false,
    reason: "Input passed all security checks",
    sanitizedOutput,
    confidence: 0.95,
    user: userId || "anon",
    ip,
    latency: Math.max(1, nowMs() - start),
  });
}
