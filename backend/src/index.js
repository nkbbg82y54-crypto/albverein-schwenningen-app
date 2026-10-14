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
        response = json({ ok: true, service: "sav-schwenningen-backend", version: "38" });
      } else if (request.method === "GET" && url.pathname === "/api/calendar.ics") {
        response = calendarResponse(url);
      } else if (request.method === "GET" && url.pathname === "/api/push/config") {
        response = json({
          enabled: Boolean(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_JWK),
          publicKey: env.VAPID_PUBLIC_KEY || "",
        });
      } else if (request.method === "POST" && url.pathname === "/api/push/subscribe") {
        response = await savePushSubscription(request, env);
      } else if (request.method === "POST" && url.pathname === "/api/push/unsubscribe") {
        response = await removePushSubscription(request, env);
      } else if (request.method === "GET" && url.pathname === "/api/push/latest") {
        response = await getLatestPushNotice(env);
      } else if (request.method === "POST" && url.pathname === "/api/change-requests") {
        response = await createChangeRequest(request, env, ctx);
      } else if (request.method === "GET" && url.pathname.startsWith("/api/content/")) {
        response = await listPublicContent(url, env);
      } else if (url.pathname.startsWith("/api/admin/")) {
        response = await handleAdminRequest(request, url, env, ctx);
      } else if (url.pathname.startsWith("/api/manage/")) {
        url.pathname = url.pathname.replace(/^\/api\/manage\//, "/api/admin/");
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
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(sendAutomaticEventReminders(env, new Date(controller.scheduledTime)));
  },
};

async function handleAdminRequest(request, url, env, ctx) {
  const actor = await authenticateAdmin(request, env);
  if (!actor) return json({ error: "Unauthorized" }, 401);

  if (request.method === "GET" && url.pathname === "/api/admin/login") {
    const token = await createAdminSessionToken(actor.email, env.DATA_ENCRYPTION_KEY);
    return new Response(null, {
      status: 302,
      headers: { location: `${env.ALLOWED_ORIGIN}/?v=38#admin-session=${token}` },
    });
  }

  if (request.method === "GET" && url.pathname === "/api/admin/me") {
    return json({
      email: actor.email,
      displayName: actor.display_name,
      roleLabel: actor.role_label,
      permissions: actor.permissions,
    });
  }

  if (request.method === "GET" && url.pathname === "/api/admin/backup") {
    requirePermission(actor, "manage_admins");
    const rows = await env.DB.prepare(
      `SELECT id, resource_type, payload_json, sort_order, published,
              created_at, updated_at, updated_by
       FROM content_items
       ORDER BY resource_type, sort_order, created_at`,
    ).all();
    const content = { events: [], notices: [], board: [], gallery: [] };
    for (const row of rows.results) {
      if (!Object.hasOwn(content, row.resource_type)) continue;
      content[row.resource_type].push({
        id: row.id,
        payload: JSON.parse(row.payload_json),
        sortOrder: row.sort_order,
        published: Boolean(row.published),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        updatedBy: row.updated_by,
      });
    }
    const itemCount = Object.values(content).reduce((sum, items) => sum + items.length, 0);
    ctx.waitUntil(audit(env, actor.email, "backup.export", "content", null, { itemCount }));
    return json({
      format: "sav-schwenningen-content-backup",
      version: 1,
      generatedAt: new Date().toISOString(),
      content,
    });
  }

  if (request.method === "POST" && url.pathname === "/api/admin/push/send") {
    const body = await readBrowserAction(request, env);
    const isEvent = typeof body.eventId === "string";
    const resourceType = isEvent ? "events" : "notices";
    const contentId = isEvent ? body.eventId : (typeof body.noticeId === "string" ? body.noticeId : "");
    requirePermission(actor, isEvent ? "events_manage" : "notices_manage");
    const content = await env.DB.prepare(
      "SELECT id, payload_json FROM content_items WHERE id = ?1 AND resource_type = ?2 AND published = 1",
    ).bind(contentId, resourceType).first();
    if (!content) return json({ error: isEvent ? "Published event not found" : "Published notice not found" }, 404);
    if (isContentArchived(resourceType, JSON.parse(content.payload_json), berlinReminderContext().localDate)) {
      return json({ error: "Archived content cannot be pushed" }, 409);
    }
    if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_JWK) return json({ error: "Push is not configured" }, 503);
    const now = new Date().toISOString();
    await env.DB.prepare(
      `INSERT INTO push_state (state_key, notice_id, updated_at)
       VALUES ('current', ?1, ?2)
       ON CONFLICT(state_key) DO UPDATE SET notice_id = excluded.notice_id, updated_at = excluded.updated_at`,
    ).bind(contentId, now).run();
    const result = await sendPushBroadcast(env);
    ctx.waitUntil(audit(env, actor.email, "push.send", isEvent ? "event" : "notice", contentId, result));
    return json(result);
  }

  if (request.method === "GET" && url.pathname === "/api/admin/push/stats") {
    requirePermission(actor, "notices_manage");
    const stats = await env.DB.prepare(
      "SELECT COUNT(*) AS total, MAX(updated_at) AS latest_subscription_at FROM push_subscriptions",
    ).first();
    return json({
      total: Number(stats?.total || 0),
      latestSubscriptionAt: stats?.latest_subscription_at || null,
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

  const changeActionMatch = url.pathname.match(/^\/api\/admin\/change-requests\/([0-9a-f-]+)\/action$/i);
  if (changeActionMatch && request.method === "POST") {
    requirePermission(actor, "changes_view");
    const body = await readBrowserAction(request, env);
    if (body.action === "status") {
      return updateChangeRequestStatus(env, ctx, actor, changeActionMatch[1], body.status);
    }
    if (body.action === "delete") {
      return deleteChangeRequest(env, ctx, actor, changeActionMatch[1]);
    }
    return json({ error: "Invalid action" }, 400);
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
    return updateChangeRequestStatus(env, ctx, actor, changeMatch[1], body.status);
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

  const contentActionMatch = url.pathname.match(/^\/api\/admin\/content\/(events|notices|board|gallery)(?:\/([0-9a-f-]+))?\/action$/i);
  if (contentActionMatch && request.method === "POST") {
    const body = await readBrowserAction(request, env);
    const method = body.action === "create" ? "POST" : body.action === "update" ? "PUT" : body.action === "delete" ? "DELETE" : null;
    if (!method) return json({ error: "Invalid action" }, 400);
    if (method !== "POST" && !contentActionMatch[2]) return json({ error: "Item id required" }, 400);
    const forwarded = new Request(request.url, {
      method,
      headers: method === "DELETE" ? {} : { "content-type": "application/json" },
      ...(method === "DELETE" ? {} : { body: JSON.stringify(body.input) }),
    });
    return handleAdminContent(
      forwarded,
      env,
      ctx,
      actor,
      contentActionMatch[1].toLowerCase(),
      contentActionMatch[2],
    );
  }

  const resourceMatch = url.pathname.match(/^\/api\/admin\/content\/(events|notices|board|gallery)(?:\/([0-9a-f-]+))?$/i);
  if (resourceMatch) {
    return handleAdminContent(request, env, ctx, actor, resourceMatch[1].toLowerCase(), resourceMatch[2]);
  }

  return json({ error: "Not found" }, 404);
}

async function updateChangeRequestStatus(env, ctx, actor, id, status) {
  const allowedStatuses = new Set(["new", "in_progress", "completed", "deleted"]);
  if (!allowedStatuses.has(status)) return json({ error: "Invalid status" }, 400);
  const now = new Date().toISOString();
  const completed = status === "completed" ? now : null;
  const result = await env.DB.prepare(
    `UPDATE change_requests
     SET status = ?1, updated_at = ?2, completed_at = ?3, completed_by = ?4
     WHERE id = ?5 AND status != 'deleted'`,
  ).bind(status, now, completed, completed ? actor.email : null, id).run();
  if (!result.meta.changes) return json({ error: "Not found" }, 404);
  ctx.waitUntil(audit(env, actor.email, "change_request.status", "change_request", id, { status }));
  return json({ ok: true, status });
}

async function deleteChangeRequest(env, ctx, actor, id) {
  const result = await env.DB.prepare(
    "DELETE FROM change_requests WHERE id = ?1",
  ).bind(id).run();
  if (!result.meta.changes) return json({ error: "Not found" }, 404);
  ctx.waitUntil(audit(env, actor.email, "change_request.delete", "change_request", id));
  return json({ ok: true });
}

async function handleAdminContent(request, env, ctx, actor, resourceType, id) {
  requirePermission(actor, RESOURCE_PERMISSIONS[resourceType]);

  if (request.method === "GET" && !id) {
    const rows = await env.DB.prepare(
      `SELECT id, payload_json, sort_order, published, created_at, updated_at, updated_by
       FROM content_items WHERE resource_type = ?1
       ORDER BY sort_order, updated_at DESC`,
    ).bind(resourceType).all();
    const today = berlinReminderContext().localDate;
    return json({ items: rows.results.map((row) => {
      const item = formatContentRow(row);
      return { ...item, archived: isContentArchived(resourceType, item.payload, today) };
    }) });
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
  const today = berlinReminderContext().localDate;
  return json({ items: rows.results.map(formatContentRow).filter((item) => !isContentArchived(resourceType, item.payload, today)) });
}

function calendarResponse(url) {
  const content = buildCalendarFile({
    title: url.searchParams.get("title") || "",
    startDate: url.searchParams.get("startDate") || "",
    endDate: url.searchParams.get("endDate") || "",
    startTime: url.searchParams.get("startTime") || "",
    endTime: url.searchParams.get("endTime") || "",
    location: url.searchParams.get("location") || "",
  });
  return new Response(content, {
    headers: {
      "content-type": "text/calendar; charset=utf-8",
      "content-disposition": 'attachment; filename="albverein-termin.ics"',
      "content-language": "de",
    },
  });
}

export function buildCalendarFile(input) {
  const title = String(input.title || "").trim();
  const startDate = String(input.startDate || "").trim();
  const endDate = String(input.endDate || "").trim();
  const startTime = String(input.startTime || "").trim();
  const endTime = String(input.endTime || "").trim();
  const location = String(input.location || "").trim();
  if (!title || title.length > 120) throw new HttpError(400, "Invalid event title");
  if (!isCalendarDate(startDate)) throw new HttpError(400, "Invalid start date");
  if (endDate && (!isCalendarDate(endDate) || endDate < startDate)) throw new HttpError(400, "Invalid end date");
  if (startTime && !/^([01]\d|2[0-3]):[0-5]\d$/.test(startTime)) throw new HttpError(400, "Invalid start time");
  if (endTime && (!startTime || !/^([01]\d|2[0-3]):[0-5]\d$/.test(endTime))) throw new HttpError(400, "Invalid end time");
  if (location.length > 160) throw new HttpError(400, "Invalid location");
  const compactStart = startDate.replaceAll("-", "");
  const compactEnd = (endDate || startDate).replaceAll("-", "");
  const timeValue = (value) => value.replace(":", "") + "00";
  const slug = title.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "termin";
  const lines = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "CALSCALE:GREGORIAN",
    "METHOD:PUBLISH",
    "PRODID:-//Albverein Schwenningen//Termine//DE",
    "BEGIN:VEVENT",
    `UID:${compactStart}-${startTime ? timeValue(startTime) : "allday"}-${slug}@sav-schwenningen.de`,
    `DTSTAMP:${new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "")}`,
  ];
  if (startTime) {
    lines.push(`DTSTART:${compactStart}T${timeValue(startTime)}`);
    if (endDate || endTime) {
      const effectiveEndTime = endTime || startTime;
      if ((endDate || startDate) === startDate && effectiveEndTime <= startTime) throw new HttpError(400, "End must be after start");
      lines.push(`DTEND:${compactEnd}T${timeValue(effectiveEndTime)}`);
    }
  } else {
    lines.push(`DTSTART;VALUE=DATE:${compactStart}`);
    lines.push(`DTEND;VALUE=DATE:${nextCalendarDate(endDate || startDate).replaceAll("-", "")}`);
  }
  lines.push(`SUMMARY:${escapeCalendarText(title)}`);
  if (location) lines.push(`LOCATION:${escapeCalendarText(location)}`);
  lines.push("DESCRIPTION:Termin der Ortsgruppe Schwenningen/Heuberg", "END:VEVENT", "END:VCALENDAR", "");
  return lines.join("\r\n");
}

function isCalendarDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

function nextCalendarDate(value) {
  return shiftIsoDate(value, 1);
}

export function shiftIsoDate(value, days) {
  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day + days));
  return date.toISOString().slice(0, 10);
}

export function isContentArchived(resourceType, payload, today) {
  if (resourceType === "events") return String(payload.endDate || payload.date || "") < today;
  if (resourceType === "notices") return String(payload.date || "") < shiftIsoDate(today, -90);
  return false;
}

function escapeCalendarText(value) {
  return value.replace(/\\/g, "\\\\").replace(/\r?\n/g, "\\n").replace(/([,;])/g, "\\$1");
}

async function savePushSubscription(request, env) {
  requireAllowedOrigin(request, env);
  if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_JWK) return json({ error: "Push is not configured" }, 503);
  const subscription = await readJson(request);
  const endpoint = typeof subscription?.endpoint === "string" ? subscription.endpoint.trim() : "";
  if (!endpoint.startsWith("https://") || endpoint.length > 2000) throw new HttpError(400, "Invalid push subscription");
  const serialized = JSON.stringify(subscription);
  if (serialized.length > 10_000) throw new HttpError(413, "Push subscription too large");
  const id = await sha256Base64Url(endpoint);
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO push_subscriptions (id, endpoint, subscription_json, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?4)
     ON CONFLICT(endpoint) DO UPDATE SET subscription_json = excluded.subscription_json, updated_at = excluded.updated_at`,
  ).bind(id, endpoint, serialized, now).run();
  return json({ ok: true });
}

async function removePushSubscription(request, env) {
  requireAllowedOrigin(request, env);
  const body = await readJson(request);
  const endpoint = typeof body?.endpoint === "string" ? body.endpoint.trim() : "";
  if (!endpoint) throw new HttpError(400, "Invalid push subscription");
  await env.DB.prepare("DELETE FROM push_subscriptions WHERE endpoint = ?1").bind(endpoint).run();
  return json({ ok: true });
}

async function getLatestPushNotice(env) {
  const row = await env.DB.prepare(
    `SELECT c.resource_type, c.payload_json
     FROM push_state s
     JOIN content_items c ON c.id = s.notice_id
     WHERE s.state_key = 'current' AND c.published = 1`,
  ).first();
  if (!row) return json({ error: "No push message" }, 404);
  const payload = JSON.parse(row.payload_json);
  if (row.resource_type === "events") {
    const sameDay = await env.DB.prepare(
      `SELECT payload_json FROM content_items
       WHERE resource_type = 'events' AND published = 1
         AND json_extract(payload_json, '$.date') = ?1
       ORDER BY sort_order, updated_at DESC`,
    ).bind(payload.date || "").all();
    const events = sameDay.results.map((item) => JSON.parse(item.payload_json));
    if (events.length > 1) {
      return json({
        title: `Erinnerung: ${events.length} Termine`,
        body: `${formatGermanEventDate(payload.date)}: ${events.map((event) => event.title).join(" · ")}`,
        url: `${env.ALLOWED_ORIGIN}/#termine`,
      });
    }
    return json({
      title: `Erinnerung: ${payload.title || "Termin des Albvereins"}`,
      body: eventPushBody(payload),
      url: `${env.ALLOWED_ORIGIN}/#termine`,
    });
  }
  return json({
    title: payload.title || "Neue Meldung vom Albverein",
    body: payload.text || "In der App gibt es eine neue Meldung.",
    url: `${env.ALLOWED_ORIGIN}/#meldungen`,
  });
}

function formatGermanEventDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value || "")) return "Termin";
  return new Intl.DateTimeFormat("de-DE", { timeZone: "Europe/Berlin", dateStyle: "medium" })
    .format(new Date(`${value}T12:00:00Z`));
}

function eventPushBody(event) {
  const details = [formatGermanEventDate(event.date)];
  if (event.time) details.push(`${event.time} Uhr`);
  if (event.location) details.push(event.location);
  return details.join(" · ");
}

export function berlinReminderContext(date = new Date()) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/Berlin",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date).filter((part) => part.type !== "literal").map((part) => [part.type, part.value]));
  const localDate = `${parts.year}-${parts.month}-${parts.day}`;
  return { localDate, hour: Number(parts.hour), reminderDate: nextCalendarDate(localDate) };
}

async function sendAutomaticEventReminders(env, scheduledAt = new Date()) {
  const context = berlinReminderContext(scheduledAt);
  if (context.hour !== 18 || !env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_JWK) return { skipped: true };
  const due = await env.DB.prepare(
    `SELECT c.id FROM content_items c
     LEFT JOIN push_state s ON s.state_key = ('event-reminder:' || c.id || ':' || json_extract(c.payload_json, '$.date'))
     WHERE c.resource_type = 'events' AND c.published = 1
       AND json_extract(c.payload_json, '$.date') = ?1
       AND s.state_key IS NULL
     ORDER BY c.sort_order, c.updated_at DESC`,
  ).bind(context.reminderDate).all();
  if (!due.results.length) return { skipped: true };
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO push_state (state_key, notice_id, updated_at)
     VALUES ('current', ?1, ?2)
     ON CONFLICT(state_key) DO UPDATE SET notice_id = excluded.notice_id, updated_at = excluded.updated_at`,
  ).bind(due.results[0].id, now).run();
  const result = await sendPushBroadcast(env);
  await env.DB.batch(due.results.map((event) => env.DB.prepare(
    `INSERT INTO push_state (state_key, notice_id, updated_at)
     VALUES (?1, ?2, ?3)
     ON CONFLICT(state_key) DO UPDATE SET notice_id = excluded.notice_id, updated_at = excluded.updated_at`,
  ).bind(`event-reminder:${event.id}:${context.reminderDate}`, event.id, now)));
  return result;
}

async function sendPushBroadcast(env) {
  const rows = await env.DB.prepare(
    "SELECT id, endpoint FROM push_subscriptions ORDER BY updated_at DESC LIMIT 500",
  ).all();
  let sent = 0;
  let failed = 0;
  const expired = [];
  await Promise.all(rows.results.map(async (subscription) => {
    try {
      const authorization = await createVapidAuthorization(subscription.endpoint, env);
      const response = await fetch(subscription.endpoint, {
        method: "POST",
        headers: {
          authorization,
          ttl: "60",
          urgency: "normal",
        },
      });
      if (response.ok) sent += 1;
      else if (response.status === 404 || response.status === 410) expired.push(subscription.id);
      else failed += 1;
    } catch (error) {
      console.error("push_delivery_failed", error);
      failed += 1;
    }
  }));
  if (expired.length) {
    await env.DB.batch(expired.map((id) => env.DB.prepare("DELETE FROM push_subscriptions WHERE id = ?1").bind(id)));
  }
  return { ok: true, sent, failed, removed: expired.length, total: rows.results.length };
}

export async function createVapidAuthorization(endpoint, env) {
  const audience = new URL(endpoint).origin;
  const header = encodeBase64UrlText(JSON.stringify({ typ: "JWT", alg: "ES256" }));
  const payload = encodeBase64UrlText(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 60 * 60,
    sub: env.VAPID_SUBJECT || "mailto:app@sav-schwenningen.de",
  }));
  let jwk;
  try {
    jwk = JSON.parse(env.VAPID_PRIVATE_JWK);
  } catch {
    throw new HttpError(503, "Invalid VAPID configuration");
  }
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signingInput = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(signingInput),
  );
  const token = `${signingInput}.${toBase64Url(new Uint8Array(signature))}`;
  return `vapid t=${token}, k=${env.VAPID_PUBLIC_KEY}`;
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return toBase64Url(new Uint8Array(digest));
}

function requireAllowedOrigin(request, env) {
  if (request.headers.get("origin") !== env.ALLOWED_ORIGIN) throw new HttpError(403, "Forbidden origin");
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
  const notificationStatus = env.EMAIL || env.NOTIFICATION_WEBHOOK_URL ? "pending" : "disabled";
  await env.DB.prepare(
    `INSERT INTO change_requests
     (id, request_type, encrypted_payload, encryption_iv, status, notification_status, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, 'new', ?5, ?6, ?6)`,
  ).bind(id, input.requestType, encrypted.ciphertext, encrypted.iv, notificationStatus, now).run();

  if (env.EMAIL || env.NOTIFICATION_WEBHOOK_URL) {
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
  if (serialized.length > 250_000) throw new HttpError(413, "Content payload too large");
  return {
    payload: body.payload,
    sortOrder: Number.isInteger(body.sortOrder) ? body.sortOrder : 0,
    published: Boolean(body.published),
  };
}

async function authenticateAdmin(request, env) {
  const authorization = request.headers.get("authorization") || "";
  const sessionToken = authorization.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
  let email = "";
  if (sessionToken) {
    email = await verifyAdminSessionToken(sessionToken, env.DATA_ENCRYPTION_KEY);
  } else {
    const assertion = request.headers.get("Cf-Access-Jwt-Assertion");
    if (!assertion || !env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;
    const claims = await verifyAccessJwt(assertion, env.ACCESS_TEAM_DOMAIN, env.ACCESS_AUD);
    email = String(claims.email || "").trim().toLowerCase();
  }
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

async function createAdminSessionToken(email, secret) {
  if (!secret) throw new HttpError(503, "Session service not configured");
  const payload = encodeBase64UrlText(JSON.stringify({
    email: String(email).trim().toLowerCase(),
    exp: Math.floor(Date.now() / 1000) + 12 * 60 * 60,
  }));
  const key = await importAdminSessionKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return `${payload}.${toBase64Url(new Uint8Array(signature))}`;
}

async function verifyAdminSessionToken(token, secret) {
  if (!secret) throw new HttpError(401, "Invalid session");
  const parts = token.split(".");
  if (parts.length !== 2) throw new HttpError(401, "Invalid session");
  const key = await importAdminSessionKey(secret);
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    fromBase64Url(parts[1]),
    new TextEncoder().encode(parts[0]),
  );
  if (!valid) throw new HttpError(401, "Invalid session");
  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[0])));
  } catch {
    throw new HttpError(401, "Invalid session");
  }
  if (!payload.email || !Number.isFinite(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) {
    throw new HttpError(401, "Session expired");
  }
  return String(payload.email).trim().toLowerCase();
}

async function importAdminSessionKey(secret) {
  const source = fromBase64(secret);
  const context = new TextEncoder().encode("sav-admin-session-v1");
  const combined = new Uint8Array(source.length + context.length);
  combined.set(source);
  combined.set(context, source.length);
  const derived = await crypto.subtle.digest("SHA-256", combined);
  return crypto.subtle.importKey("raw", derived, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
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
    let sent = false;
    if (env.EMAIL) {
      const typeLabel = requestType === "bank" ? "Bankverbindung" : "Adressänderung";
      await sendEmail(env, {
        subject: `Neue Änderungsmitteilung: ${typeLabel}`,
        text: `In der SAV-App ist eine neue Änderungsmitteilung eingegangen.\n\nArt: ${typeLabel}\nEingang: ${createdAt}\nVorgang: ${id}\n\nDie persönlichen Angaben stehen ausschließlich im geschützten Adminbereich:\nhttps://app.sav-schwenningen.de/#admin`,
      });
      sent = true;
    } else if (env.NOTIFICATION_WEBHOOK_URL) {
      const response = await fetch(env.NOTIFICATION_WEBHOOK_URL, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(env.NOTIFICATION_WEBHOOK_TOKEN ? { authorization: `Bearer ${env.NOTIFICATION_WEBHOOK_TOKEN}` } : {}),
        },
        body: JSON.stringify({ id, requestType, createdAt, containsSensitiveData: true }),
      });
      sent = response.ok;
    }
    await env.DB.prepare(
      "UPDATE change_requests SET notification_status = ?1 WHERE id = ?2",
    ).bind(sent ? "sent" : "failed", id).run();
  } catch (error) {
    console.error("notification_failed", error);
    await env.DB.prepare(
      "UPDATE change_requests SET notification_status = 'failed' WHERE id = ?1",
    ).bind(id).run();
  }
}

async function sendEmail(env, { subject, text }) {
  const from = "app@sav-schwenningen.de";
  const to = "app@sav-schwenningen.de";
  return env.EMAIL.send({ from, to, subject, text });
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
  if (text.length > 300_000) throw new HttpError(413, "Request too large");
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "Invalid JSON");
  }
}

async function readBrowserAction(request, env) {
  if (request.headers.get("origin") !== env.ALLOWED_ORIGIN) throw new HttpError(403, "Forbidden origin");
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().startsWith("text/plain")) throw new HttpError(415, "Plain text JSON required");
  const text = await request.text();
  if (text.length > 300_000) throw new HttpError(413, "Request too large");
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
    "access-control-allow-headers": "Authorization, Content-Type, Cf-Access-Jwt-Assertion",
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

function toBase64Url(bytes) {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function encodeBase64UrlText(value) {
  return toBase64Url(new TextEncoder().encode(value));
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
