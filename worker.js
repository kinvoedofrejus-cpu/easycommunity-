/**
 * EasyCommunity — API backend (Cloudflare Worker + D1)
 * ------------------------------------------------------
 * Toutes les données (membres, cotisations, comptabilité, rapports,
 * paramètres) sont stockées de façon centralisée dans D1, afin que
 * l'administrateur, le secrétaire et le trésorier voient et modifient
 * les mêmes données depuis n'importe quel appareil.
 *
 * Déploiement rapide :
 *   1. wrangler d1 create easycommunity
 *   2. Copier le database_id retourné dans wrangler.toml
 *   3. wrangler d1 execute easycommunity --file=./schema.sql --remote
 *   4. wrangler deploy
 *
 * Secrets (TOKEN_SECRET, PASSWORD_PEPPER, LICENSE_SECRET) :
 *   Aucune variable à configurer avec "wrangler secret put" — les trois
 *   sont codées en dur juste ci-dessous. Rien à faire, rien à oublier.
 *   LICENSE_SECRET doit rester strictement identique à celle de keygen.html.
 *
 * Système de licence :
 *   Tant qu'aucune licence valide n'est activée par l'administrateur
 *   (menu Paramètres), toutes les routes de données (/api/data,
 *   /api/members, /api/dues, etc.) renvoient une erreur 402 — pour
 *   TOUS les comptes, y compris l'administrateur. Seules les routes
 *   /api/login, /api/license/status et /api/license/activate restent
 *   accessibles, afin que l'administrateur puisse toujours se
 *   connecter et saisir une clé de licence pour débloquer l'application.
 *
 * Au tout premier appel, si la table "users" est vide, un compte
 * administrateur par défaut est créé automatiquement :
 *   admin / admin123   (à changer immédiatement)
 */

const TABLES = ["members", "dues", "transactions", "reports"];
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12h

// Secret de licence codé en dur (pas de "wrangler secret put" à faire).
// DOIT être strictement identique à la constante LICENSE_SECRET de keygen.html.
const LICENSE_SECRET = "9666b32428b6edb941e4b1d556ca33997f8f3d6f584f4ac9b7ab3e32dd459ab2";

// Secrets d'authentification codés en dur (pas de variable à configurer).
const TOKEN_SECRET = "ce63bfeeed42868927de6496f7d7ba24eea96186a3f265c8c9222bc307cd304b";
const PASSWORD_PEPPER = "2187419df59c95175c0b56249d6ec603232b116e927c226fd0166548a6ceef8d";

function cors(origin) {
  return {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}
function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { "Content-Type": "application/json", ...cors(origin) },
  });
}

/* ---------- crypto helpers ---------- */
function b64url(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function b64urlToBytes(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}
async function hashPassword(password, pepper) {
  const data = new TextEncoder().encode(password + ":" + pepper);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function signToken(payload, secret) {
  const enc = new TextEncoder();
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  return body + "." + b64url(new Uint8Array(sig));
}
async function verifyToken(token, secret) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("HMAC", key, b64urlToBytes(sig), enc.encode(body));
  if (!ok) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(body)));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) { return null; }
}

/* ---------- license key verification (HMAC, format YYYY-MM-DD.sigHex) ---------- */
async function verifyLicenseKey(key, secret) {
  if (!key || typeof key !== "string" || !key.includes(".")) return null;
  const [expires, sig] = key.trim().split(".");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(expires) || !sig) return null;
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const macBuf = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(expires));
  const macHex = Array.from(new Uint8Array(macBuf)).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 20);
  if (macHex !== sig.toLowerCase()) return null;
  return { expires };
}
async function getLicenseStatus(env) {
  const row = await env.DB.prepare("SELECT expires FROM license WHERE id=1").first();
  if (!row || !row.expires) return { active: false, expires: null };
  const active = new Date(row.expires + "T23:59:59Z").getTime() >= Date.now();
  return { active, expires: row.expires };
}

/* ---------- bootstrap (first run) ---------- */
async function ensureBootstrap(env) {
  const row = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
  if (row && row.c > 0) return;
  const hash = await hashPassword("admin123", PASSWORD_PEPPER);
  await env.DB.prepare("INSERT INTO users (id,name,email,password_hash,role,active) VALUES (?,?,?,?,?,1)")
    .bind("admin-" + Date.now(), "Administrateur", "admin", hash, "administrateur").run();
  const defaultSettings = {
    name: "EasyCommunity", shortName: "EC", address: "", phone: "", email: "", website: "",
    regNumber: "", president: "", currency: "FCFA", createdDate: "", slogan: "Gérer • Connecter • Développer", logo: "",
  };
  await env.DB.prepare("INSERT OR IGNORE INTO settings (id, data) VALUES (1, ?)").bind(JSON.stringify(defaultSettings)).run();
}

/* ---------- generic table helpers (members/dues/transactions/reports) ---------- */
async function listRows(env, table) {
  const { results } = await env.DB.prepare(`SELECT data FROM ${table}`).all();
  return results.map((r) => JSON.parse(r.data));
}
async function insertRow(env, table, obj) {
  await env.DB.prepare(`INSERT INTO ${table} (id, data) VALUES (?, ?)`).bind(obj.id, JSON.stringify(obj)).run();
}
async function updateRow(env, table, id, obj) {
  await env.DB.prepare(`UPDATE ${table} SET data=? WHERE id=?`).bind(JSON.stringify(obj), id).run();
}
async function getRow(env, table, id) {
  const r = await env.DB.prepare(`SELECT data FROM ${table} WHERE id=?`).bind(id).first();
  return r ? JSON.parse(r.data) : null;
}
async function deleteRow(env, table, id) {
  await env.DB.prepare(`DELETE FROM ${table} WHERE id=?`).bind(id).run();
}

/* ---------- auth ---------- */
async function authenticate(request, env) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  const payload = await verifyToken(token, TOKEN_SECRET);
  if (!payload) return null;
  return payload; // {uid, name, role, exp}
}
function forbidIfNotRole(auth, roles, origin) {
  if (!roles.includes(auth.role)) return json({ error: "Rôle non autorisé pour cette action." }, 403, origin);
  return null;
}

/* ---------- route handlers ---------- */
async function handleLogin(request, env, origin) {
  const body = await request.json().catch(() => ({}));
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";
  if (!email || !password) return json({ error: "E-mail et mot de passe requis." }, 400, origin);
  const user = await env.DB.prepare("SELECT * FROM users WHERE lower(email)=? AND active=1").bind(email).first();
  if (!user) return json({ error: "Identifiants incorrects ou compte désactivé." }, 401, origin);
  const hash = await hashPassword(password, PASSWORD_PEPPER);
  if (hash !== user.password_hash) return json({ error: "Identifiants incorrects ou compte désactivé." }, 401, origin);
  const payload = { uid: user.id, name: user.name, role: user.role, exp: Date.now() + TOKEN_TTL_MS };
  const token = await signToken(payload, TOKEN_SECRET);
  return json({ token, user: { id: user.id, name: user.name, role: user.role } }, 200, origin);
}

async function handleLicenseStatus(env, origin) {
  const lic = await getLicenseStatus(env);
  return json(lic, 200, origin);
}
async function handleLicenseActivate(request, env, origin) {
  const body = await request.json().catch(() => ({}));
  const key = (body.key || "").trim();
  const result = await verifyLicenseKey(key, LICENSE_SECRET);
  if (!result) return json({ error: "Clé de licence invalide." }, 400, origin);
  await env.DB.prepare(
    "INSERT INTO license (id,key_value,expires,updated_at) VALUES (1,?,?,?) ON CONFLICT(id) DO UPDATE SET key_value=excluded.key_value, expires=excluded.expires, updated_at=excluded.updated_at"
  ).bind(key, result.expires, new Date().toISOString()).run();
  return json({ active: true, expires: result.expires }, 200, origin);
}

async function handleGetData(env, auth, origin) {
  const [settingsRow, members, dues, transactions, reports] = await Promise.all([
    env.DB.prepare("SELECT data FROM settings WHERE id=1").first(),
    listRows(env, "members"),
    listRows(env, "dues"),
    listRows(env, "transactions"),
    listRows(env, "reports"),
  ]);
  const settings = settingsRow ? JSON.parse(settingsRow.data) : {};
  let users;
  if (auth.role === "administrateur") {
    const { results } = await env.DB.prepare("SELECT id,name,email,role,active FROM users").all();
    users = results;
  }
  return json({ settings, members, dues, transactions, reports, users, me: { id: auth.uid, name: auth.name, role: auth.role } }, 200, origin);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "*";
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") return new Response(null, { headers: cors(origin) });

    // Toute route qui ne commence pas par /api/ sert le site statique
    // (public/index.html et éventuels autres fichiers du dossier public/).
    if (!path.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    try {
      await ensureBootstrap(env);

      if (path === "/api/login" && method === "POST") return await handleLogin(request, env, origin);
      if (path === "/api/license/status" && method === "GET") return await handleLicenseStatus(env, origin);

      const auth = await authenticate(request, env);
      if (!auth) return json({ error: "Non authentifié." }, 401, origin);

      // L'activation de licence doit rester accessible à l'admin même
      // quand la licence est inactive/expirée, sinon il ne pourrait
      // jamais la renouveler.
      if (path === "/api/license/activate" && method === "POST") {
        const f = forbidIfNotRole(auth, ["administrateur"], origin); if (f) return f;
        return await handleLicenseActivate(request, env, origin);
      }

      // Verrou global : tant que la licence (détenue par l'administrateur)
      // n'est pas active, aucun compte — admin inclus — n'accède aux données.
      const lic = await getLicenseStatus(env);
      if (!lic.active) {
        return json({ error: "license_inactive", message: "Licence inactive ou expirée.", expires: lic.expires }, 402, origin);
      }

      if (path === "/api/data" && method === "GET") return await handleGetData(env, auth, origin);

      // ---- Members (admin only) ----
      if (path === "/api/members" && method === "POST") {
        const f = forbidIfNotRole(auth, ["administrateur"], origin); if (f) return f;
        const body = await request.json();
        await insertRow(env, "members", body);
        return json(body, 201, origin);
      }
      let m;
      if ((m = path.match(/^\/api\/members\/([^/]+)$/)) && method === "PUT") {
        const f = forbidIfNotRole(auth, ["administrateur"], origin); if (f) return f;
        const body = await request.json();
        await updateRow(env, "members", m[1], body);
        return json(body, 200, origin);
      }
      if ((m = path.match(/^\/api\/members\/([^/]+)$/)) && method === "DELETE") {
        const f = forbidIfNotRole(auth, ["administrateur"], origin); if (f) return f;
        await deleteRow(env, "members", m[1]);
        return json({ ok: true }, 200, origin);
      }

      // ---- Dues / cotisations (admin only) ----
      if (path === "/api/dues" && method === "POST") {
        const f = forbidIfNotRole(auth, ["administrateur"], origin); if (f) return f;
        const body = await request.json();
        await insertRow(env, "dues", body);
        return json(body, 201, origin);
      }

      // ---- Transactions / comptabilité (admin + trésorier) ----
      if (path === "/api/transactions" && method === "POST") {
        const f = forbidIfNotRole(auth, ["administrateur", "tresorier"], origin); if (f) return f;
        const body = await request.json();
        await insertRow(env, "transactions", body);
        return json(body, 201, origin);
      }
      if ((m = path.match(/^\/api\/transactions\/([^/]+)$/)) && method === "DELETE") {
        const f = forbidIfNotRole(auth, ["administrateur", "tresorier"], origin); if (f) return f;
        await deleteRow(env, "transactions", m[1]);
        return json({ ok: true }, 200, origin);
      }

      // ---- Reports / rapports & réunions ----
      if (path === "/api/reports" && method === "POST") {
        const f = forbidIfNotRole(auth, ["secretaire", "tresorier"], origin); if (f) return f;
        const body = await request.json();
        await insertRow(env, "reports", body);
        return json(body, 201, origin);
      }
      if ((m = path.match(/^\/api\/reports\/([^/]+)$/)) && method === "PATCH") {
        const f = forbidIfNotRole(auth, ["administrateur"], origin); if (f) return f;
        const existing = await getRow(env, "reports", m[1]);
        if (!existing) return json({ error: "Rapport introuvable." }, 404, origin);
        const body = await request.json();
        const updated = { ...existing, status: body.status, observations: body.observations ?? existing.observations };
        await updateRow(env, "reports", m[1], updated);
        return json(updated, 200, origin);
      }

      // ---- Settings (admin only writes) ----
      if (path === "/api/settings" && method === "PUT") {
        const f = forbidIfNotRole(auth, ["administrateur"], origin); if (f) return f;
        const body = await request.json();
        await env.DB.prepare("INSERT INTO settings (id,data) VALUES (1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data").bind(JSON.stringify(body)).run();
        return json(body, 200, origin);
      }

      // ---- Users (admin only) ----
      if (path === "/api/users" && method === "POST") {
        const f = forbidIfNotRole(auth, ["administrateur"], origin); if (f) return f;
        const body = await request.json();
        if (!body.password) return json({ error: "Mot de passe requis." }, 400, origin);
        const hash = await hashPassword(body.password, PASSWORD_PEPPER);
        await env.DB.prepare("INSERT INTO users (id,name,email,password_hash,role,active) VALUES (?,?,?,?,?,1)")
          .bind(body.id, body.name, body.email, hash, body.role).run();
        return json({ id: body.id, name: body.name, email: body.email, role: body.role, active: true }, 201, origin);
      }
      if ((m = path.match(/^\/api\/users\/([^/]+)$/)) && method === "PUT") {
        const f = forbidIfNotRole(auth, ["administrateur"], origin); if (f) return f;
        const body = await request.json();
        if (body.password) {
          const hash = await hashPassword(body.password, PASSWORD_PEPPER);
          await env.DB.prepare("UPDATE users SET name=?, email=?, role=?, active=?, password_hash=? WHERE id=?")
            .bind(body.name, body.email, body.role, body.active ? 1 : 0, hash, m[1]).run();
        } else {
          await env.DB.prepare("UPDATE users SET name=?, email=?, role=?, active=? WHERE id=?")
            .bind(body.name, body.email, body.role, body.active ? 1 : 0, m[1]).run();
        }
        return json({ id: m[1], name: body.name, email: body.email, role: body.role, active: body.active }, 200, origin);
      }

      return json({ error: "Route inconnue." }, 404, origin);
    } catch (err) {
      return json({ error: "Erreur serveur : " + err.message }, 500, origin);
    }
  },
};
