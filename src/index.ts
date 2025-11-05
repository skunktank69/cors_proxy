import { LRUCache } from "lru-cache";

const cache = new LRUCache<string, Response>({
  max: 500, // Max 500 entries
  ttl: 1000 * 60 * 5, // 5 minutes TTL
});

const RATE_LIMIT_WINDOW = 10 * 1000; // 10 seconds
const RATE_LIMIT_COUNT = 10; // 10 requests per window per IP
const rateMap = new Map<string, { count: number; reset: number }>();

function rateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = rateMap.get(ip) || { count: 0, reset: now + RATE_LIMIT_WINDOW };

  if (now > entry.reset) {
    entry.count = 1;
    entry.reset = now + RATE_LIMIT_WINDOW;
  } else {
    entry.count++;
  }

  rateMap.set(ip, entry);
  return entry.count > RATE_LIMIT_COUNT;
}

function isSafeTarget(target: string): boolean {
  try {
    const u = new URL(target);
    if (!["http:", "https:"].includes(u.protocol)) return false;
    if (["localhost", "127.0.0.1", "::1"].includes(u.hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

export default {
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/") {
      return new Response("CORS Proxy active", {
        status: 200,
        headers: { "content-type": "text/plain" },
      });
    }

    if (url.pathname !== "/proxy") {
      return new Response("Not Found", { status: 404 });
    }

    const target = url.searchParams.get("url");
    if (!target) {
      return new Response(JSON.stringify({ error: "Missing ?url=" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }

    const ip = req.headers.get("CF-Connecting-IP") || "unknown";
    if (rateLimit(ip)) {
      return new Response(JSON.stringify({ error: "Rate limit exceeded" }), {
        status: 429,
        headers: { "content-type": "application/json" },
      });
    }

    if (!isSafeTarget(target)) {
      return new Response(JSON.stringify({ error: "Unsafe or invalid URL" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }

    // Cache check
    const cached = cache.get(target);
    if (cached && req.method === "GET") {
      const resp = cached.clone();
      resp.headers.set("x-cache", "HIT");
      return resp;
    }

    try {
      let body: BodyInit | undefined = undefined;

      if (!["GET", "HEAD"].includes(req.method)) {
        // Cloudflare Workers require full buffering, no streaming passthrough
        body = await req.arrayBuffer();
      }

      const proxied = await fetch(target, {
        method: req.method,
        headers: req.headers,
        body,
        redirect: "follow",
      });

      // Clone and clean headers
      const newHeaders = new Headers(proxied.headers);
      newHeaders.set("Access-Control-Allow-Origin", "*");
      newHeaders.set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
      newHeaders.set("x-proxied-by", "Cloudflare-CORS-Proxy");
      newHeaders.delete("content-encoding");
      newHeaders.delete("transfer-encoding");
      newHeaders.delete("connection");

      const resp = new Response(proxied.body, {
        status: proxied.status,
        headers: newHeaders,
      });

      if (req.method === "GET" && proxied.status === 200) {
        cache.set(target, resp.clone());
      }

      return resp;
    } catch (err: any) {
      return new Response(JSON.stringify({ error: err.message || "Unknown error" }), {
        status: 500,
        headers: { "content-type": "application/json" },
      });
    }
  },
};
