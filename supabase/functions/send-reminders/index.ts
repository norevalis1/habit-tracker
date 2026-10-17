// =====================================================================
// SUPABASE EDGE FUNCTION: send-reminders
//
// Two jobs:
//  1. Every 5 minutes a scheduler calls this with a secret. We ask the
//     database "who is due a reminder?" and send each person a push
//     notification.
//  2. The app's "Send a test" button calls it with the person's login,
//     and we send them a test notification (at most one a minute).
//
// Push messages are encrypted (standard Web Push, RFC 8291) and signed
// with your private key (VAPID, RFC 8292). No extra libraries are needed:
// everything below uses the browser-standard "crypto" built into Supabase.
//
// Secrets this function needs (Supabase > Edge Functions > Secrets):
//   VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, CRON_SECRET
// (Supabase provides SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY itself.)
//
// Deploy with "Verify JWT" OFF: this function checks logins itself.
// =====================================================================

// A fixed version (the same one the app uses), so a redeploy never pulls in a surprise update.
import { createClient } from "npm:@supabase/supabase-js@2.117.2";

// ---------- WEB PUSH CRYPTO (START) ----------
const enc = new TextEncoder();
const b64uToBytes = (s: string): Uint8Array => {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
};
const bytesToB64u = (u: Uint8Array): string => {
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

// Sign a short-lived "this message really comes from our server" token (VAPID).
async function vapidAuthHeader(endpoint: string, publicKey: string, privateKey: string, subject: string): Promise<string> {
  const pub = b64uToBytes(publicKey); // 65 bytes: 0x04 + x + y
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: bytesToB64u(pub.slice(1, 33)), y: bytesToB64u(pub.slice(33, 65)), d: privateKey },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"],
  );
  const header = bytesToB64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = bytesToB64u(enc.encode(JSON.stringify({
    aud: new URL(endpoint).origin,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: subject,
  })));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(header + "." + claims)));
  return "vapid t=" + header + "." + claims + "." + bytesToB64u(sig) + ", k=" + publicKey;
}

// Encrypt a message so only the person's phone can read it (RFC 8291, aes128gcm).
// "fixed" lets tests supply a known salt and key; real sends leave it out.
async function encryptPayload(
  payload: Uint8Array, p256dh: string, authSecret: string,
  fixed?: { salt?: Uint8Array; privateJwk?: JsonWebKey },
): Promise<Uint8Array> {
  const uaPublic = b64uToBytes(p256dh);
  const auth = b64uToBytes(authSecret);
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);

  let asPrivate: CryptoKey, asPublic: Uint8Array;
  if (fixed?.privateJwk) {
    asPrivate = await crypto.subtle.importKey("jwk", fixed.privateJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    asPublic = concat(new Uint8Array([4]), b64uToBytes(fixed.privateJwk.x!), b64uToBytes(fixed.privateJwk.y!));
  } else {
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    asPrivate = pair.privateKey;
    asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  }
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, asPrivate, 256));

  const hkdf = async (salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, bytes: number) => {
    const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, bytes * 8));
  };
  const salt = fixed?.salt ?? crypto.getRandomValues(new Uint8Array(16));
  const ikm = await hkdf(auth, ecdh, concat(enc.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);

  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, concat(payload, new Uint8Array([2]))));
  // Header: salt (16) + record size (4) + key length (1) + our public key (65)
  return concat(salt, new Uint8Array([0, 0, 16, 0]), new Uint8Array([asPublic.length]), asPublic, cipher);
}
// ---------- WEB PUSH CRYPTO (END) ----------

type Sub = { id: string; endpoint: string; p256dh: string; auth: string };

// Send one notification. Returns "ok", "gone" (phone unsubscribed), or "failed".
async function sendPush(sub: Sub, message: { title: string; body: string }, env: { pub: string; priv: string; subject: string }) {
  try {
    // Only ever talk to the real phone-push services (never an arbitrary website).
    if (!/^https:\/\/(fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com|[a-z0-9.-]+\.push\.apple\.com|[a-z0-9.-]+\.notify\.windows\.com)\//.test(sub.endpoint)) return "gone";
    const body = await encryptPayload(enc.encode(JSON.stringify(message)), sub.p256dh, sub.auth);
    const res = await fetch(sub.endpoint, {
      method: "POST",
      redirect: "manual",
      headers: {
        "Authorization": await vapidAuthHeader(sub.endpoint, env.pub, env.priv, env.subject),
        "Content-Encoding": "aes128gcm",
        "Content-Type": "application/octet-stream",
        "TTL": "7200",          // if the phone is off, drop the reminder after 2 hours
        "Urgency": "normal",
      },
      body,
    });
    if (res.status === 404 || res.status === 410) return "gone";
    if (!res.ok) { console.error("push failed", res.status, await res.text()); return "failed"; }
    await res.body?.cancel();
    return "ok";
  } catch (e) {
    console.error("push error", String(e));
    return "failed";
  }
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-cron-secret",
};
const reply = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { ...CORS, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  // "stage" remembers what we were doing, so if something fails the reply says where.
  let stage = "start";
  try {
    stage = "read settings";
    const url = Deno.env.get("SUPABASE_URL");
    const serviceKey = Deno.env.get("SB_SECRET_KEY") ?? Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !serviceKey) return reply({ error: "Missing SUPABASE_URL or service key (stage: " + stage + ")" }, 500);
    const env = {
      pub: Deno.env.get("VAPID_PUBLIC_KEY") ?? "",
      priv: Deno.env.get("VAPID_PRIVATE_KEY") ?? "",
      subject: Deno.env.get("VAPID_SUBJECT") ?? "https://norevalis1.github.io/habit-tracker/",
    };
    if (!env.pub || !env.priv) return reply({ error: "VAPID keys are not set" }, 500);

    stage = "connect";
    const admin = createClient(url, serviceKey, { auth: { persistSession: false } });
    const cronSecret = Deno.env.get("CRON_SECRET");
    // Compare secrets in a way that takes the same time whether or not they match.
    const sameSecret = async (a: string, b: string) => {
      const [x, y] = await Promise.all([a, b].map(async (v) => new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(v)))));
      let diff = 0;
      for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
      return diff === 0;
    };
    const isCron = !!cronSecret && await sameSecret(req.headers.get("x-cron-secret") ?? "", cronSecret);

    const subsFor = async (userId: string): Promise<Sub[]> => {
      const { data, error } = await admin.from("push_subscriptions").select("id,endpoint,p256dh,auth").eq("user_id", userId);
      if (error) throw new Error("read subscriptions: " + error.message);
      return data ?? [];
    };
    const deliver = async (userId: string, message: { title: string; body: string }) => {
      let sent = 0;
      for (const sub of await subsFor(userId)) {
        stage = "send push";
        const result = await sendPush(sub, message, env);
        if (result === "ok") sent++;
        if (result === "gone") await admin.from("push_subscriptions").delete().eq("id", sub.id);
      }
      return sent;
    };

    // JOB 2: a signed-in person pressed "Send a test".
    if (!isCron) {
      stage = "check login";
      const token = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
      const { data, error } = await admin.auth.getUser(token);
      if (error || !data.user) return reply({ error: "Not signed in" }, 401);
      // At most one test a minute per person (the database keeps the time).
      stage = "check test limit";
      const { data: allowed, error: limitError } = await admin.rpc("claim_push_test", { uid: data.user.id });
      if (limitError) throw new Error("claim_push_test: " + limitError.message);
      if (allowed !== true) return reply({ error: "Wait a minute before sending another test." }, 429);
      stage = "load subscriptions";
      const sent = await deliver(data.user.id, { title: "Habits", body: "Reminders are working. \u{1F33F}" });
      return reply({ sent });
    }

    // JOB 1: the scheduler. Who is due a reminder right now?
    stage = "find due reminders";
    const { data: due, error } = await admin.rpc("due_reminders");
    if (error) throw new Error("due_reminders: " + error.message);
    const byUser = new Map<string, { names: string[]; ids: string[]; day: Map<string, string> }>();
    for (const row of due ?? []) {
      const entry = byUser.get(row.user_id) ?? { names: [], ids: [], day: new Map() };
      entry.names.push(row.name); entry.ids.push(row.habit_id); entry.day.set(row.habit_id, row.local_day);
      byUser.set(row.user_id, entry);
    }
    let sent = 0;
    for (const [userId, entry] of byUser) {
      const body = entry.names.length === 1 ? "Time for “" + entry.names[0] + "”." : "Time for: " + entry.names.join(", ");
      sent += await deliver(userId, { title: "Habits", body });
      // Remember we reminded today, so there is never a repeat.
      stage = "mark reminded";
      for (const id of entry.ids) await admin.from("habits").update({ last_reminded: entry.day.get(id) }).eq("id", id);
    }
    return reply({ users: byUser.size, sent });
  } catch (e) {
    console.error("stage:", stage, e);
    return reply({ error: "Something went wrong at '" + stage + "': " + String((e as Error)?.message ?? e).slice(0, 200) }, 500);
  }
});
