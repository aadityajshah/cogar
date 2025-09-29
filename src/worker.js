export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const selfOrigin = url.origin;
    const allowedOrigins = ["https://www.aadityashah.com", "https://aadityashah.com"]; // allowed external sites
    const primaryRedirect = "https://www.aadityashah.com";
    const referer = request.headers.get("Referer") || "";
    const origin = request.headers.get("Origin") || "";
    const accept = request.headers.get("Accept") || "";
    const isWs = request.headers.get("Upgrade") === "websocket";
    const isNavigation = !isWs && request.method === "GET" && accept.includes("text/html");

    const originFrom = (v) => { try { return new URL(v).origin; } catch { return "" } };
    const refOrigin = originFrom(referer);
    const reqOrigin = originFrom(origin);
    const fromExternal = allowedOrigins.includes(refOrigin) || allowedOrigins.includes(reqOrigin);
    const fromSelf = (refOrigin === selfOrigin) || (reqOrigin === selfOrigin);

    let isAllowed = false;
    const bypass = env.ALLOW_DEV && String(env.ALLOW_DEV).toLowerCase() === "true";
    if (bypass) {
      isAllowed = true;
    } else if (isNavigation) {
      // Only allow top-level navigations when coming from allowed external sites
      isAllowed = fromExternal;
    } else {
      // Allow assets/WS from our own origin and also permit external referrers
      isAllowed = fromExternal || fromSelf;
    }

    // Block all traffic unless referred by allowedOrigin
    if (!isAllowed) {
      if (isWs) {
        return new Response("Forbidden", { status: 403 });
      }
      return Response.redirect(primaryRedirect, 302);
    }

    if (url.pathname === "/ws") {
      if (request.headers.get("Upgrade") !== "websocket") {
        return new Response("Expected WebSocket", { status: 426 });
      }
      const id = env.CHAT_ROOM.idFromName("global");
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request);
    }

    // Serve static assets from /public
    if (env.ASSETS && typeof env.ASSETS.fetch === "function") {
      return env.ASSETS.fetch(request);
    }
    return new Response("Not found", { status: 404 });
  },
}

// Durable Object: manages connections and broadcasts
export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Map(); // ws -> username
  }

  async fetch(request) {
    const { searchParams } = new URL(request.url);
    const [client, server] = Object.values(new WebSocketPair());

    // Determine username from JA4 if available; otherwise, fallback
    const username = await this.deriveUsername(request);

    await this.handleSession(server, username);

    return new Response(null, { status: 101, webSocket: client });
  }

  async deriveUsername(request) {
    try {
      // Prefer Cloudflare Bot Management fields if present (plan dependent)
      // request.cf may include botManagement with JA3/JA4 fields in some plans.
      const cf = request.cf || {};
      const bm = cf.botManagement || {};
      const ja4 = bm.ja4 || bm.ja4Hash || null;
      if (ja4 && typeof ja4 === "string") return `ja4_${ja4.slice(0, 12)}`;
    } catch (_) {}

    // Fallback: pseudo-fingerprint hashed over stable headers within a 72h bucket
    const headers = request.headers;
    const ua = headers.get("user-agent") || "";
    const accept = headers.get("accept") || "";
    const lang = headers.get("accept-language") || "";
    const enc = headers.get("accept-encoding") || "";

    // 72-hour time bucket so username is stable inside the window but rotates after
    const now = Date.now();
    const bucket = Math.floor(now / (72 * 60 * 60 * 1000));

    const data = `${ua}\n${accept}\n${lang}\n${enc}\n${bucket}`;
    const salt = this.env.USERNAME_SALT || "default_salt";
    const digest = await hmacSha256Hex(salt, data);
    return `anon_${digest.slice(0, 12)}`;
  }

  async handleSession(ws, username) {
    ws.accept();

    // Save active session
    this.sessions.set(ws, username);

    // Inform this client of their username so UI can style own messages
    try { ws.send(JSON.stringify({ type: "hello", username })); } catch (_){}

    // Send recent messages from last 72 hours
    const history = await this.loadRecentMessages();
    for (const msg of history) {
      ws.send(JSON.stringify({ type: "history", ...msg }));
    }

    // Broadcast join (send to everyone, including the joining user)
    await this.persistAndBroadcast({ kind: "system", text: `${username} joined`, username, ts: Date.now() });

    ws.addEventListener("message", async (ev) => {
      try {
        const text = typeof ev.data === "string" ? ev.data : "";
        if (!text.trim()) return;
        const payload = { kind: "chat", text, username, ts: Date.now() };
        await this.persistAndBroadcast(payload);
      } catch (e) {
        // noop
      }
    });

    ws.addEventListener("close", async () => {
      this.sessions.delete(ws);
      await this.persistAndBroadcast({ kind: "system", text: `${username} left`, username, ts: Date.now() });
    });

    ws.addEventListener("error", () => {
      try { ws.close(); } catch (_) {}
      this.sessions.delete(ws);
    });
  }

  async loadRecentMessages() {
    // List last ~200 messages from KV within prefix for current 72h bucket
    const bucket = Math.floor(Date.now() / (72 * 60 * 60 * 1000));
    const prefix = `m:${bucket}:`;
    const res = await this.env.CHAT_KV.list({ prefix, limit: 200 });
    const items = [];
    for (const key of res.keys) {
      const v = await this.env.CHAT_KV.get(key.name, { type: "json" });
      if (v) items.push(v);
    }
    // Sort ascending by timestamp
    items.sort((a, b) => (a.ts || 0) - (b.ts || 0));
    return items;
  }

  async persistAndBroadcast(payload) {
    // Persist with 72-hour TTL; key includes ts for ordering
    const bucket = Math.floor(payload.ts / (72 * 60 * 60 * 1000));
    const key = `m:${bucket}:${payload.ts}:${Math.random().toString(36).slice(2, 8)}`;
    await this.env.CHAT_KV.put(key, JSON.stringify(payload), { expirationTtl: 72 * 60 * 60 });

    const message = JSON.stringify({ type: "event", ...payload });
    for (const [sock] of this.sessions) {
      try { sock.send(message); } catch (_) {}
    }
  }
}

async function hmacSha256Hex(key, msg) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}
