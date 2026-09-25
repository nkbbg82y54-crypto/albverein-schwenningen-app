const RESOURCE_PERMISSIONS = {
  events: "events_manage",
  notices: "notices_manage",
  board: "board_manage",
  gallery: "gallery_manage",
};

const ALLOWED_PERMISSIONS = new Set([
  ...Object.values(RESOURCE_PERMISSIONS),
  "changes_view",
  "manage_admins",
]);

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cors = corsHeaders(request, env);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      let response;

      if (request.method === "GET" && url.pathname === "/health") {
        response = json({ ok: true, service: "sav-schwenningen-backend" });
      } else if (request.method === "POST" && url.pathname === "/api/change-requests") {
        response = await createChangeRequest(request, env, ctx);
      } else if (request.method === "GET" && url.pathname.startsWith("/api/content/")) {
        response = await listPublicContent(url, env);
      } else if (url.pathname.startsWith("/api/admin/")) {
        response = await handleAdminRequest(request, url, env, ctx);
      } else {
        response = json({ error: "Not found" }, 404);
      }

      return withHeaders(response, cors);
    } catch (error) {
      if (error instanceof HttpError) {
        return withHeaders(json({ error: error.message }, error.status), cors);
      }
      console.error("request_failed", error);
      return withHeaders(json({ error: "Internal server error" }, 500), cors);
    }
  },
};

async function handleAdminRequest(request, url, env, ctx) {
  const actor = await authenticateAdmin(request, env);
  if (!actor) return json({ error: "Unauthorized" }, 401);

  if (request.method === "GET" && url.pathname === "/api/admin/me") {
    return json({
      email: actor.email,
      displayName: actor.display_name,
      roleLabel: actor.role_label,
      permissions: actor.permissions,
    });
  }

  if (url.pathname === "/api/admin/change-requests" && request.method === "GET") {
    requirePermission(actor, "changes_view");
    const rows = await env.DB.prepare(
      `SELECT id, request_type, status, notification_status, created_at, updated_at
       FROM change_requests
       WHERE status != 'deleted'
       ORDER BY created_at DESC
       LIMIT 200`,
    ).all();
    return json({ items: rows.results });
  }

  const changeMatch = url.pathname.match(/^\/api\/admin\/change-requests\/([0-9a-f-]+)$/i);
  if (changeMatch && request.method === "GET") {
    requirePermission(actor, "changes_view");
    const row = await env.DB.prepare(
      `SELECT id, request_type, encrypted_payload, encryption_iv, status,
              notification_status, created_at, updated_at
       FROM change_requests WHERE id = ?1 AND status != 'deleted'`,
    ).bind(changeMatch[1]).first();
    if (!row) return json({ error: "Not found" }, 404);
    const payload = await decryptPayload(row.encrypted_payload, row.encryption_iv, env.DATA_ENCRYPTION_KEY);
    return json({
      id: row.id,
      requestType: row.request_type,
      status: row.status,
      notificationStatus: row.notification_status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      payload,
    });
  }

  if (changeMatch && request.method === "PATCH") {
    requirePermission(actor, "changes_view");
    const body = await readJson(request);
    const allowedStatuses = new Set(["new", "in_progress", "completed", "deleted"]);
    if (!allowedStatuses.has(body.status)) return json({ error: "Invalid status" }, 400);
    const now = new Date().toISOString();
    const completed = body.status === "completed" ? now : null;
    const result = await env.DB.prepare(
      `UPDATE change_requests
       SET status = ?1, updated_at = ?2, completed_at = ?3, completed_by = ?4
       WHERE id = ?5`,
    ).bind(body.status, now, completed, completed ? actor.email : null, changeMatch[1]).run();
    if (!result.meta.changes) return json({ error: "Not found" }, 404);
    ctx.waitUntil(audit(env, actor.email, "change_request.status", "change_request", changeMatch[1], { status: body.status }));
    return json({ ok: true });
  }

  if (url.pathname === "/api/admin/admins" && request.method === "GET") {
    requirePermission(actor, "manage_admins");
    const rows = await env.DB.prepare(
      `SELECT a.email, a.display_name, a.role_label, a.active,
              GROUP_CONCAT(p.permission) AS permissions
       FROM admins a
       LEFT JOIN admin_permissions p ON p.admin_email = a.email
       GROUP BY a.email
       ORDER BY a.created_at`,
    ).all();
    return json({
      items: rows.results.map((row) => ({
        email: row.email,
        displayName: row.display_name,
        roleLabel: row.role_label,
        active: Boolean(row.active),
        permissions: row.permissions ? row.permissions.split(",") : [],
      })),
    });
  }

  const permissionMatch = url.pathname.match(/^\/api\/admin\/admins\/([^/]+)\/permissions$/);
  if (permissionMatch && request.method === "PUT") {
    requirePermission(actor, "manage_admins");
    const email = decodeURIComponent(permissionMatch[1]).trim().toLowerCase();
    if (email === actor.email) return json({ error: "Own permissions cannot be changed here" }, 400);
    const body = await readJson(request);
    const permissions = [...new Set(Array.isArray(body.permissions) ? body.permissions : [])];
    if (permissions.some((permission) => !ALLOWED_PERMISSIONS.has(permission))) {
      return json({ error: "Invalid permission" }, 400);
    }
    const target = await env.DB.prepare("SELECT email FROM admins WHERE email = ?1 AND active = 1").bind(email).first();
    if (!target) return json({ error: "Admin not found" }, 404);
    const now = new Date().toISOString();
    const statements = [
      env.DB.prepare("DELETE FROM admin_permissions WHERE admin_email = ?1").bind(email),
      ...permissions.map((permission) => env.DB.prepare(
        `INSERT INTO admin_permissions (admin_email, permission, granted_at, granted_by)
         VALUES (?1, ?2, ?3, ?4)`,
      ).bind(email, permission, now, actor.email)),
    ];
    await env.DB.batch(statements);
    ctx.waitUntil(audit(env, actor.email, "admin.permissions", "admin", email, { permissions }));
    return json({ ok: true, permissions });
  }

  const resourceMatch = url.pathname.match(/^\/api\/admin\/content\/(events|notices|board|gallery)(?:\/([0-9a-f-]+))?$/i);
  if (resourceMatch) {
    return handleAdminContent(request, env, ctx, actor, resourceMatch[1].toLowerCase(), resourceMatch[2]);
  }

  return json({ error: "Not found" }, 404);
}

async function handleAdminContent(request, env, ctx, actor, resourceType, id) {
  requirePermission(actor, RESOURCE_PERMISSIONS[resourceType]);

  if (request.method === "GET" && !id) {
    const rows = await env.DB.prepare(
      `SELECT id, payload_json, sort_order, published, created_at, updated_at, updated_by
       FROM content_items WHERE resource_type = ?1
       ORDER BY sort_order, updated_at DESC`,
    ).bind(resourceType).all();
    return json({ items: rows.results.map(formatContentRow) });
  }

  if (request.method === "POST" && !id) {
    const input = validateContentInput(await readJson(request));
    const itemId = crypto.randomUUID();
    const now = new Date().toISOString();
    await env.DB.prepare(
      `INSERT INTO content_items
       (id, resource_type, payload_json, sort_order, published, created_at, updated_at, updated_by)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)`,
    ).bind(itemId, resourceType, JSON.stringify(input.payload), input.sortOrder, input.published ? 1 : 0, now, actor.email).run();
    ctx.waitUntil(audit(env, actor.email, "content.create", resourceType, itemId));
    return json({ id: itemId }, 201);
  }

  if (request.method === "PUT" && id) {
    const input = validateContentInput(await readJson(request));
    const now = new Date().toISOString();
    const result = await env.DB.prepare(
      `UPDATE content_items
       SET payload_json = ?1, sort_order = ?2, published = ?3, updated_at = ?4, updated_by = ?5
       WHERE id = ?6 AND resource_type = ?7`,
    ).bind(JSON.stringify(input.payload), input.sortOrder, input.published ? 1 : 0, now, actor.email, id, resourceType).run();
    if (!result.meta.changes) return json({ error: "Not found" }, 404);
    ctx.waitUntil(audit(env, actor.email, "content.update", resourceType, id));
    return json({ ok: true });
  }

  if (request.method === "DELETE" && id) {
    const result = await env.DB.prepare(
      "DELETE FROM content_items WHERE id = ?1 AND resource_type = ?2",
    ).bind(id, resourceType).run();
    if (!result.meta.changes) return json({ error: "Not found" }, 404);
    ctx.waitUntil(audit(env, actor.email, "content.delete", resourceType, id));
    return json({ ok: true });
  }

  return json({ error: "Method not allowed" }, 405);
}

async function listPublicContent(url, env) {
  const resourceType = url.pathname.split("/").pop().toLowerCase();
  if (!RESOURCE_PERMISSIONS[resourceType]) return json({ error: "Not found" }, 404);
  const rows = await env.DB.prepare(
    `SELECT id, payload_json, sort_order, updated_at
     FROM content_items
     WHERE resource_type = ?1 AND published = 1
     ORDER BY sort_order, updated_at DESC`,
  ).bind(resourceType).all();
  return json({ items: rows.results.map(formatContentRow) });
}

async function createChangeRequest(request, env, ctx) {
  if (!env.DATA_ENCRYPTION_KEY) return json({ error: "Service not configured" }, 503);
  const input = validateChangeRequest(await readJson(request));
  if (env.TURNSTILE_SECRET) {
    const verified = await verifyTurnstile(input.turnstileToken, request, env.TURNSTILE_SECRET);
    if (!verified) return json({ error: "Security check failed" }, 400);
  }
  delete input.turnstileToken;
  const encrypted = await encryptPayload(input.payload, env.DATA_ENCRYPTION_KEY);
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const notificationStatus = env.NOTIFICATION_WEBHOOK_URL ? "pending" : "disabled";
  await env.DB.prepare(
    `INSERT INTO change_requests
     (id, request_type, encrypted_payload, encryption_iv, status, notification_status, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, 'new', ?5, ?6, ?6)`,
  ).bind(id, input.requestType, encrypted.ciphertext, encrypted.iv, notificationStatus, now).run();

  if (env.NOTIFICATION_WEBHOOK_URL) {
    ctx.waitUntil(sendNotification(env, id, input.requestType, now));
  }
  return json({ ok: true, id }, 201);
}

export function validateChangeRequest(body) {
  if (!body || !["address", "bank"].includes(body.requestType) || typeof body.payload !== "object" || !body.payload) {
    throw new HttpError(400, "Invalid request");
  }
  const payload = body.payload;
  const required = body.requestType === "address"
    ? ["firstName", "lastName", "memberNumber", "street", "postalCode", "city"]
    : ["name", "memberNumber", "accountHolder", "iban"];
  for (const field of required) {
    if (typeof payload[field] !== "string" || !payload[field].trim() || payload[field].length > 200) {
      throw new HttpError(400, `Invalid field: ${field}`);
    }
  }
  if (body.requestType === "bank") {
    const iban = payload.iban.replace(/\s/g, "").toUpperCase();
    if (!/^DE\d{20}$/.test(iban)) throw new HttpError(400, "Invalid IBAN");
    payload.iban = iban;
  }
  return {
    requestType: body.requestType,
    payload,
    turnstileToken: typeof body.turnstileToken === "string" ? body.turnstileToken : "",
  };
}

function validateContentInput(body) {
  if (!body || typeof body.payload !== "object" || !body.payload || Array.isArray(body.payload)) {
    throw new HttpError(400, "Invalid content payload");
  }
  const serialized = JSON.stringify(body.payload);
  if (serialized.length > 100_000) throw new HttpError(413, "Content payload too large");
  return {
    payload: body.payload,
    sortOrder: Number.isInteger(body.sortOrder) ? body.sortOrder : 0,
    published: Boolean(body.published),
  };
}

async function authenticateAdmin(request, env) {
  const assertion = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!assertion || !env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;
  const claims = await verifyAccessJwt(assertion, env.ACCESS_TEAM_DOMAIN, env.ACCESS_AUD);
  const email = String(claims.email || "").trim().toLowerCase();
  if (!email) return null;
  const admin = await env.DB.prepare(
    "SELECT email, display_name, role_label FROM admins WHERE email = ?1 AND active = 1",
  ).bind(email).first();
  if (!admin) return null;
  const permissions = await env.DB.prepare(
    "SELECT permission FROM admin_permissions WHERE admin_email = ?1",
  ).bind(email).all();
  return { ...admin, email, permissions: permissions.results.map((row) => row.permission) };
}

export async function verifyAccessJwt(token, teamDomain, audience) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new HttpError(401, "Invalid access token");
  const header = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[0])));
  const claims = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[1])));
  if (header.alg !== "RS256" || !header.kid) throw new HttpError(401, "Invalid access token");
  const normalizedDomain = teamDomain.replace(/^https?:\/\//, "").replace(/\/$/, "");
  const issuer = `https://${normalizedDomain}`;
  const now = Math.floor(Date.now() / 1000);
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== issuer || !audiences.includes(audience) || claims.exp <= now || (claims.nbf && claims.nbf > now)) {
    throw new HttpError(401, "Invalid access token claims");
  }
  const certsResponse = await fetch(`${issuer}/cdn-cgi/access/certs`, { cf: { cacheTtl: 3600, cacheEverything: true } });
  if (!certsResponse.ok) throw new HttpError(503, "Unable to validate access token");
  const jwks = await certsResponse.json();
  const jwk = jwks.keys?.find((key) => key.kid === header.kid);
  if (!jwk) throw new HttpError(401, "Unknown signing key");
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    fromBase64Url(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!valid) throw new HttpError(401, "Invalid access token signature");
  return claims;
}

export async function encryptPayload(payload, base64Key) {
  const key = await importEncryptionKey(base64Key, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return { ciphertext: toBase64(new Uint8Array(encrypted)), iv: toBase64(iv) };
}

export async function decryptPayload(ciphertext, iv, base64Key) {
  const key = await importEncryptionKey(base64Key, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(iv) },
    key,
    fromBase64(ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

async function importEncryptionKey(base64Key, usages) {
  const raw = fromBase64(base64Key);
  if (raw.byteLength !== 32) throw new Error("DATA_ENCRYPTION_KEY must contain 32 bytes");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, usages);
}

async function verifyTurnstile(token, request, secret) {
  if (!token) return false;
  const form = new FormData();
  form.set("secret", secret);
  form.set("response", token);
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) form.set("remoteip", ip);
  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
  if (!response.ok) return false;
  return Boolean((await response.json()).success);
}

async function sendNotification(env, id, requestType, createdAt) {
  try {
    const response = await fetch(env.NOTIFICATION_WEBHOOK_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(env.NOTIFICATION_WEBHOOK_TOKEN ? { authorization: `Bearer ${env.NOTIFICATION_WEBHOOK_TOKEN}` } : {}),
      },
      body: JSON.stringify({ id, requestType, createdAt, containsSensitiveData: true }),
    });
    await env.DB.prepare(
      "UPDATE change_requests SET notification_status = ?1 WHERE id = ?2",
    ).bind(response.ok ? "sent" : "failed", id).run();
  } catch (error) {
    console.error("notification_failed", error);
    await env.DB.prepare(
      "UPDATE change_requests SET notification_status = 'failed' WHERE id = ?1",
    ).bind(id).run();
  }
}

async function audit(env, actorEmail, action, targetType, targetId = null, details = null) {
  await env.DB.prepare(
    `INSERT INTO audit_log (id, actor_email, action, target_type, target_id, details_json, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
  ).bind(
    crypto.randomUUID(),
    actorEmail,
    action,
    targetType,
    targetId,
    details ? JSON.stringify(details) : null,
    new Date().toISOString(),
  ).run();
}

function requirePermission(actor, permission) {
  if (!actor.permissions.includes(permission)) throw new HttpError(403, "Forbidden");
}

function formatContentRow(row) {
  return {
    id: row.id,
    payload: JSON.parse(row.payload_json),
    sortOrder: row.sort_order,
    ...(row.published === undefined ? {} : { published: Boolean(row.published) }),
    updatedAt: row.updated_at,
    ...(row.updated_by ? { updatedBy: row.updated_by } : {}),
  };
}

async function readJson(request) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) throw new HttpError(415, "JSON required");
  const text = await request.text();
  if (text.length > 150_000) throw new HttpError(413, "Request too large");
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "Invalid JSON");
  }
}

function corsHeaders(request, env) {
  const origin = request.headers.get("origin");
  if (!origin || origin !== env.ALLOWED_ORIGIN) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "access-control-allow-headers": "Content-Type, Cf-Access-Jwt-Assertion",
    "access-control-allow-credentials": "true",
    "access-control-max-age": "86400",
    vary: "Origin",
  };
}

function withHeaders(response, headers) {
  const merged = new Headers(response.headers);
  for (const [name, value] of Object.entries(headers)) merged.set(name, value);
  merged.set("x-content-type-options", "nosniff");
  merged.set("referrer-policy", "no-referrer");
  merged.set("cache-control", "no-store");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: merged });
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function fromBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return fromBase64(normalized);
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
