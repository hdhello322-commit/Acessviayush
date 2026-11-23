// ─── Diagnostic state (module-scope, resets on isolate restart) ───
let schemaReady = false;
let schemaError = null;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathParts = url.pathname.substring(1).split('/');

    // ── Route: /dev/<token>  OR  /dev/credit/<token> ──
    let pathToken = "";
    let action    = "";

    if (pathParts[0] === 'dev') {
      if (pathParts[1] === 'credit') {
        action    = 'credit';
        pathToken = pathParts[2] || "";
      } else {
        action    = 'check';
        pathToken = pathParts[1] || "";
      }
    } else {
      return new Response("Use /dev/<token> or /dev/credit/<token>", { status: 404 });
    }

    if (!pathToken) {
      return new Response("Token required. Format: /dev/<token> or /dev/credit/<token>", { status: 400 });
    }

    // ── Helpers ──
    const nowMs         = Date.now();
    const istDateObj    = new Date(nowMs + 19800000);
    const istDateString = istDateObj.toISOString().split('T')[0];
    const escapeHtml    = (s) => String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

    // ── 1. Access token check ──
    let accessOk = false;
    try {
      const accessReq  = await fetch("https://raw.githubusercontent.com/Ayush8481Lab/Sar/refs/heads/main/app/data/access.json", {
        headers: { 'User-Agent': 'Mozilla/5.0' }
      });
      const accessData = await accessReq.json();
      if (accessData.tokens && accessData.tokens.includes(pathToken)) accessOk = true;
    } catch (err) {
      return new Response("Error validating access token.", { status: 500 });
    }

    if (!accessOk) {
      return new Response("False", {
        status: 403,
        headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" }
      });
    }

    // ── 2. Block data-centre providers ──
    const BLOCKED_KEYWORDS = ["amazon", "cloudflare", "google"];
    const asOrgRaw     = (request.cf?.asOrganization || '').toLowerCase();
    const isBlockedOrg = BLOCKED_KEYWORDS.some(kw => asOrgRaw.includes(kw));
    const allowBypass  = url.searchParams.get('allow') === '1';

    if (isBlockedOrg && !allowBypass) {
      return new Response("Blocked", {
        status: 403,
        headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" }
      });
    }

    // ── 3. D1 schema init ──
    const hasD1 = !!(env && env.LOGS_DB);
    if (hasD1 && !schemaReady) {
      try {
        await env.LOGS_DB.prepare(
          "CREATE TABLE IF NOT EXISTS logs (" +
          "id INTEGER PRIMARY KEY AUTOINCREMENT," +
          "token TEXT NOT NULL," +
          "date TEXT NOT NULL," +
          "ts TEXT NOT NULL," +
          "ua TEXT," +
          "ip TEXT," +
          "geo TEXT," +
          "action TEXT," +
          "colo TEXT" +
          ")"
        ).run();
        await env.LOGS_DB.prepare(
          "CREATE INDEX IF NOT EXISTS idx_logs_token_date ON logs(token, date)"
        ).run();
        await env.LOGS_DB.prepare(
          "CREATE INDEX IF NOT EXISTS idx_logs_date ON logs(date)"
        ).run();
        schemaReady = true;
        schemaError = null;
      } catch (e) {
        schemaError = String(e && e.message ? e.message : e);
      }
    }

    // ── 4. Log helpers ──
    const cacheKey = (token, date) => `https://dummy.internal.local/logs/${token}/${date}`;

    const getLogsForDate = async (token, dateStr) => {
      if (hasD1 && schemaReady) {
        try {
          const res = await env.LOGS_DB.prepare(
            "SELECT ts, ua, ip, geo, action, colo FROM logs WHERE token = ? AND date = ? ORDER BY id DESC LIMIT 1000"
          ).bind(token, dateStr).all();
          return res.results || [];
        } catch (e) { return []; }
      }
      try {
        const res = await caches.default.match(new Request(cacheKey(token, dateStr)));
        if (res) return (await res.json()).reverse();
      } catch (e) {}
      return [];
    };

    const appendLog = async (token, dateStr, entry) => {
      if (hasD1 && schemaReady) {
        try {
          const cutoff = new Date(Date.now() + 19800000 - 8 * 86400000).toISOString().split('T')[0];
          await env.LOGS_DB.batch([
            env.LOGS_DB.prepare(
              "INSERT INTO logs (token, date, ts, ua, ip, geo, action, colo) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            ).bind(token, dateStr, entry.ts, entry.ua, entry.ip, entry.geo, entry.action, entry.colo),
            env.LOGS_DB.prepare("DELETE FROM logs WHERE date < ?").bind(cutoff)
          ]);
        } catch (e) {}
        return;
      }
      try {
        const logs = await getLogsForDate(token, dateStr);
        logs.unshift(entry);
        const capped = logs.slice(0, 1000);
        await caches.default.put(
          new Request(cacheKey(token, dateStr)),
          new Response(JSON.stringify(capped.slice().reverse()), {
            headers: { "Cache-Control": `max-age=${8 * 86400}` }
          })
        );
      } catch (e) {}
    };

    // ── 5. Geo lookup (CF first, ip-api fallback) ──
    const buildGeoFromCF = (cf) => {
      if (!cf) return '';
      const asn     = cf.asn ? `AS${cf.asn}` : '';
      const org     = cf.asOrganization || '';
      const asnPart = [asn, org].filter(Boolean).join(' ');
      const parts   = [asnPart, cf.city, cf.region, cf.countryCode].filter(Boolean);
      return parts.length ? `[${parts.join(', ')}]` : '';
    };

    const lookupIP = async (ip, cf) => {
      const cfGeo = buildGeoFromCF(cf);
      if (cfGeo) return cfGeo;
      if (!ip || ip === 'unknown' || ip === '::1' || ip.startsWith('127.') || ip === 'localhost') return '';
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3000);
        const res = await fetch(
          `http://ip-api.com/json/${ip}?fields=status,countryCode,regionName,city,as`,
          { signal: controller.signal }
        );
        clearTimeout(timer);
        if (res.ok) {
          const data = await res.json();
          if (data.status === 'success') {
            const parts = [data.as, data.city, data.regionName, data.countryCode].filter(Boolean);
            return parts.length ? `[${parts.join(', ')}]` : '';
          }
        }
      } catch (e) {}
      return '';
    };

    // ── 6. Log this request (skip credit — don't inflate count) ──
    if (action === 'check') {
      const xff      = (request.headers.get('x-forwarded-for') || '').split(',')[0].trim();
      const cfIP     = request.headers.get('cf-connecting-ip') || '';
      const clientIP = xff || cfIP || request.headers.get('x-real-ip') || 'unknown';

      ctx.waitUntil((async () => {
        const geo     = await lookupIP(clientIP, request.cf);
        const istNow  = new Date(Date.now() + 19800000);
        const tsStr   = istNow.toISOString().replace('T', ' ').substring(0, 19) + ' IST';
        await appendLog(pathToken, istDateString, {
          ts:     tsStr,
          ua:     request.headers.get('user-agent') || 'Unknown',
          ip:     clientIP,
          geo:    geo,
          action: 'check',
          colo:   request.cf?.colo || '?'
        });
      })());
    }

    // ── 7. CHECK endpoint → plain text True ──
    if (action === 'check') {
      return new Response("True", {
        status: 200,
        headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" }
      });
    }

    // ── 8. CREDIT dashboard (last 7 days) ──
    const today = new Date(nowMs + 19800000);
    const dates = [];
    for (let i = 0; i < 7; i++) {
      dates.push(new Date(today.getTime() - i * 86400000).toISOString().split('T')[0]);
    }

    let allLogs    = [];
    let queryError = null;

    if (hasD1 && schemaReady) {
      try {
        const results = await Promise.all(
          dates.map(d =>
            env.LOGS_DB.prepare(
              "SELECT ts, ua, ip, geo, action, colo FROM logs WHERE token = ? AND date = ? ORDER BY id DESC LIMIT 1000"
            ).bind(pathToken, d).all()
          )
        );
        allLogs = results.map(r => (r && Array.isArray(r.results)) ? r.results : []);
      } catch (e) {
        queryError = String(e && e.message ? e.message : e);
        allLogs = dates.map(() => []);
      }
    } else {
      allLogs = await Promise.all(dates.map(d => getLogsForDate(pathToken, d)));
    }

    // Accurate today count via D1 COUNT(*); other days = array length (capped 1000)
    let todayCount = allLogs[0]?.length || 0;
    if (hasD1 && schemaReady) {
      try {
        const cr = await env.LOGS_DB.prepare(
          "SELECT COUNT(*) as c FROM logs WHERE token = ? AND date = ?"
        ).bind(pathToken, istDateString).first();
        todayCount = cr?.c || todayCount;
      } catch (e) {}
    }
    const counts    = [todayCount, ...allLogs.slice(1).map(l => l.length)];
    const totalLogs = counts.reduce((a, b) => a + b, 0);
    const generatedAt = new Date(Date.now() + 19800000).toISOString().replace('T', ' ').substring(0, 19) + ' IST';

    let html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Usage Logs · ${escapeHtml(pathToken)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: #0d1117; color: #c9d1d9; padding: 20px; margin: 0; line-height: 1.5; }
  h1 { color: #58a6ff; font-size: 22px; margin: 0 0 16px; }
  h2 { color: #58a6ff; font-size: 18px; margin: 28px 0 12px; }
  h3 { color: #79c0ff; font-size: 15px; margin: 0 0 10px; }
  .summary { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px 16px; margin-bottom: 16px; }
  .summary div { margin: 4px 0; }
  .day { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px 16px; margin: 12px 0; }
  .entry { font-size: 12.5px; padding: 6px 0; border-bottom: 1px solid #21262d; word-break: break-all; }
  .entry:last-child { border-bottom: none; }
  .ts { color: #79c0ff; } .ua { color: #ffa657; } .ip { color: #7ee787; } .geo { color: #d2a8ff; }
  .action { color: #f778ba; } .colo { color: #6e7681; font-size: 11px; }
  .count { color: #ff7b72; font-weight: 600; }
  code { background: #21262d; padding: 2px 6px; border-radius: 4px; color: #c9d1d9; }
  .empty { color: #6e7681; font-style: italic; }
  .warn { background: #3d1d1d; border: 1px solid #f85149; color: #ff7b72; padding: 14px 16px; border-radius: 8px; margin-bottom: 16px; line-height: 1.6; }
  .info { background: #1d2d3d; border: 1px solid #58a6ff; color: #79c0ff; padding: 14px 16px; border-radius: 8px; margin-bottom: 16px; line-height: 1.6; }
  .ok { color: #7ee787; }
  .badge-ok { background:#1a3a1a; border:1px solid #2ea043; color:#7ee787; padding:2px 8px; border-radius:6px; font-size:12px; }
  .badge-bad { background:#3d1d1d; border:1px solid #f85149; color:#ff7b72; padding:2px 8px; border-radius:6px; font-size:12px; }
  a { color: #58a6ff; }
  .generated { color: #6e7681; font-size: 11px; margin-top: 8px; }
</style>
</head>
<body>
<h1>Usage Logs · <code>${escapeHtml(pathToken)}</code></h1>`;

    if (!hasD1) {
      html += `<div class="warn"><strong>⚠️ D1 NOT BOUND.</strong> Bind a D1 database as <code>LOGS_DB</code> in Pages → Settings → Functions → Bindings.</div>`;
    } else if (!schemaReady) {
      html += `<div class="warn"><strong>⚠️ Schema not ready.</strong> Error: <code>${escapeHtml(schemaError || 'unknown')}</code></div>`;
    } else if (queryError) {
      html += `<div class="warn"><strong>⚠️ D1 query failed.</strong> <code>${escapeHtml(queryError)}</code></div>`;
    }

    if (totalLogs === 0) {
      html += `<div class="info"><strong>ℹ️ No logs yet.</strong>
        Only requests to <a href="/dev/${escapeHtml(pathToken)}"><code>/dev/${escapeHtml(pathToken)}</code></a> create log rows — visiting this dashboard does not.</div>`;
    }

    html += `<div class="summary">
  <div>Backend: ${hasD1 && schemaReady
    ? '<span class="badge-ok">D1 (global) ✓</span>'
    : '<span class="badge-bad">' + (hasD1 ? 'D1 bound, schema not ready' : 'D1 not bound (cache-based)') + '</span>'}</div>
  <div>Rendered from colo: <code>${escapeHtml(request.cf?.colo || '?')}</code></div>
  <div>Today's logged requests: <span class="count">${counts[0]}</span></div>
  <div>7‑day total logged calls: <span class="count">${totalLogs}</span></div>
  <div class="generated">Generated: ${generatedAt} · <a href="">Refresh</a></div>
</div>
<h2>Last 7 Days</h2>`;

    for (let i = 0; i < dates.length; i++) {
      const date = dates[i];
      const logs = allLogs[i] || [];
      html += `<div class="day"><h3>Date - ${date} - <span class="count">${counts[i]} calls</span></h3>`;
      if (logs.length === 0) {
        html += `<div class="entry empty">No calls recorded.</div>`;
      } else {
        logs.forEach(l => {
          html += `<div class="entry">` +
            `<span class="ts">${escapeHtml(l.ts)}</span> · ` +
            `<span class="ua">${escapeHtml(l.ua || 'Unknown')}</span> · ` +
            `<span class="ip">${escapeHtml(l.ip)}</span> ` +
            `<span class="geo">${escapeHtml(l.geo || '')}</span> · ` +
            `<span class="action">${escapeHtml(l.action || 'check')}</span> ` +
            `<span class="colo">[${escapeHtml(l.colo || '?')}]</span>` +
            `</div>`;
        });
        if (counts[i] > logs.length) {
          html += `<div class="entry empty">…and ${counts[i] - logs.length} more (display capped at 1000/day)</div>`;
        }
      }
      html += `</div>`;
    }
    html += `</body></html>`;

    return new Response(html, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "CDN-Cache-Control": "no-store"
      }
    });
  }
};
