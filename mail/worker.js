// Avio.AI mail watcher — a Cloudflare Worker (free plan) that watches the operator's mailboxes (Gmail / Google Workspace,
// and Microsoft 365 / Outlook) for emails that belong to troubleshooting cases, saves each one (with its attachments) to
// the operator's private cases repo under inbox/, and sends a push notification to the technician's phone. The app then
// offers to import the email into the case. Several mailboxes can be connected; each is checked every 2 minutes.
//
// It reads only what belongs to a case, decided per message:
//   - the subject carries a case tag  [Case <TAIL>-<CODE>]  (the app puts it in every subject it writes), or
//   - the subject carries a ticket number the app has recorded on a case, or
//   - the message is in an email thread already captured, or
//   - the sender is on the watched-senders list (addresses or @domains, set from the app).
// Nothing else is opened beyond the headers needed to decide. Access to every mailbox is read-only.
//
// Bindings (wrangler.toml / dashboard):  KV namespace MAIL
// Secrets: GITHUB_TOKEN                             (fine-grained, Contents: Read and write on the cases repo)
//          CASES_REPO                               (owner/name)
//          SETUP_KEY                                (a long random string; the app sends it to talk to this worker)
//          GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET   (for Google mailboxes: OAuth web client, Gmail read-only scope)
// Vars:    MS_CLIENT_ID                             (for Microsoft mailboxes: Entra app, public client, Mail.Read)
//          MS_TENANT                                (optional: the operator's tenant id; default "organizations")
//          APP_ORIGIN (CORS origin of the app), VAPID_SUBJECT (mailto: address for push services)
// Cron trigger: every 2 minutes.

const GMAIL = 'https://gmail.googleapis.com/gmail/v1/users/me';
const GRAPH = 'https://graph.microsoft.com/v1.0/me';
const SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';
const MS_SCOPE = 'offline_access User.Read Mail.Read';
const msAuth = env => `https://login.microsoftonline.com/${env.MS_TENANT || 'organizations'}/oauth2/v2.0`;
const TAG_RX = /\[Case\s+([A-Z0-9]{1,10}-[A-Z0-9]{4})\]/i;
const MAX_ATT = 8 * 1024 * 1024;       // attachments larger than this are listed, not stored
const MAX_TEXT = 40000;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const cors = { 'Access-Control-Allow-Origin': env.APP_ORIGIN || '*', 'Access-Control-Allow-Headers': 'authorization, content-type', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS' };
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...cors, 'content-type': 'application/json' } });
    const authed = () => (req.headers.get('authorization') || '') === 'Bearer ' + env.SETUP_KEY;
    try {
      // Google: a browser sign-in that comes back to /auth/callback
      if (url.pathname === '/auth/start') {
        if (url.searchParams.get('k') !== env.SETUP_KEY) return html('This link is not valid.', 403);
        if (!env.GOOGLE_CLIENT_ID) return html('Google mailboxes are not set up on this mail watcher.', 400);
        const state = await hmac(env.SETUP_KEY, 'state:' + Math.floor(Date.now() / 600000));
        const q = new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, redirect_uri: url.origin + '/auth/callback', response_type: 'code', scope: SCOPE, access_type: 'offline', prompt: 'consent select_account', state });
        return Response.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + q, 302);
      }
      if (url.pathname === '/auth/callback') {
        const st = url.searchParams.get('state'), t = Math.floor(Date.now() / 600000);
        if (st !== await hmac(env.SETUP_KEY, 'state:' + t) && st !== await hmac(env.SETUP_KEY, 'state:' + (t - 1))) return html('This sign-in link expired. Start again from the app.', 403);
        if (url.searchParams.get('error')) return html('Google sign-in was not completed: ' + esc(url.searchParams.get('error')) + '. Start again from the app.', 400);
        const tok = await googleToken(env, { code: url.searchParams.get('code'), redirect_uri: url.origin + '/auth/callback', grant_type: 'authorization_code' });
        if (!tok.refresh_token) return html('Google did not return a long-lived token. Start again from the app.', 400);
        const prof = await (await fetch(GMAIL + '/profile', { headers: { Authorization: 'Bearer ' + tok.access_token } })).json();
        await addBox(env, 'google', prof.emailAddress || '', tok.refresh_token);
        return html(`Mailbox connected: <b>${esc(prof.emailAddress || '')}</b>. You can close this page and go back to the app.`);
      }
      if (!authed()) return json({ error: 'not authorized' }, 401);
      // Microsoft: device sign-in. The app shows a code; the user enters it at microsoft.com/devicelogin.
      if (url.pathname === '/auth/ms/start' && req.method === 'POST') {
        if (!env.MS_CLIENT_ID) return json({ error: 'Microsoft mailboxes are not set up on this mail watcher yet (MS_CLIENT_ID). See the setup guide.' }, 400);
        const r = await fetch(msAuth(env) + '/devicecode', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: env.MS_CLIENT_ID, scope: MS_SCOPE }) });
        const j = await r.json(); if (!r.ok) return json({ error: 'Microsoft: ' + (j.error_description || j.error || r.status).split('\r')[0] }, 400);
        await env.MAIL.put('msdc', j.device_code, { expirationTtl: Math.max(60, +j.expires_in || 900) });
        return json({ code: j.user_code, url: j.verification_uri, expires: +j.expires_in || 900, interval: +j.interval || 5 });
      }
      if (url.pathname === '/auth/ms/check' && req.method === 'POST') {
        const dc = await env.MAIL.get('msdc'); if (!dc) return json({ error: 'The sign-in code expired. Start again.' });
        const r = await fetch(msAuth(env) + '/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: env.MS_CLIENT_ID, grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: dc }) });
        const j = await r.json();
        if (j.error === 'authorization_pending' || j.error === 'slow_down') return json({ pending: true });
        if (!r.ok || !j.refresh_token) { await env.MAIL.delete('msdc'); return json({ error: 'Microsoft: ' + String(j.error_description || j.error || 'no long-lived token').split('\r')[0] }); }
        await env.MAIL.delete('msdc');
        const me = await (await fetch(GRAPH + '?$select=mail,userPrincipalName', { headers: { Authorization: 'Bearer ' + j.access_token } })).json();
        const email = me.mail || me.userPrincipalName || '';
        await addBox(env, 'microsoft', email, j.refresh_token);
        return json({ ok: true, email });
      }
      if (url.pathname === '/mailbox/remove' && req.method === 'POST') {
        const { id } = await req.json();
        await env.MAIL.put('boxes', JSON.stringify((await boxes(env)).filter(b => b.id !== id)));
        for (const k of ['rt:', 'last:', 'err:']) await env.MAIL.delete(k + id);
        return json({ ok: true });
      }
      if (url.pathname === '/status') {
        const cfg = await getCfg(env), B = await boxes(env);
        const list = await Promise.all(B.map(async b => ({ id: b.id, kind: b.kind, email: b.email, last: +(await env.MAIL.get('last:' + b.id) || 0), error: (await env.MAIL.get('err:' + b.id)) || '' })));
        return json({ boxes: list, gmail: (list.find(b => b.kind === 'google') || {}).email || null, google: !!env.GOOGLE_CLIENT_ID, microsoft: !!env.MS_CLIENT_ID,
          last: Math.max(0, ...list.map(b => b.last)), lastError: (await env.MAIL.get('err')) || '', vapid: (await vapidKeys(env)).pub, subs: (await getJ(env, 'subs', [])).length, senders: cfg.senders, tickets: cfg.tickets.length, repo: env.CASES_REPO });
      }
      if (url.pathname === '/subscribe' && req.method === 'POST') {
        const { subscription } = await req.json();
        if (!subscription || !subscription.endpoint || !subscription.keys) return json({ error: 'bad subscription' }, 400);
        const subs = (await getJ(env, 'subs', [])).filter(s => s.endpoint !== subscription.endpoint);
        subs.push({ endpoint: subscription.endpoint, keys: subscription.keys, at: Date.now() });
        await env.MAIL.put('subs', JSON.stringify(subs.slice(-10)));
        return json({ ok: true, subs: subs.length });
      }
      if (url.pathname === '/config' && req.method === 'POST') {
        const b = await req.json(), cfg = await getCfg(env);
        if (Array.isArray(b.senders)) cfg.senders = b.senders.map(s => String(s).trim().toLowerCase()).filter(Boolean).slice(0, 100);
        if (Array.isArray(b.tickets)) cfg.tickets = [...new Set(b.tickets.map(s => String(s).trim()).filter(s => s.length >= 4))].slice(0, 500);
        await env.MAIL.put('cfg', JSON.stringify(cfg));
        return json({ ok: true, senders: cfg.senders, tickets: cfg.tickets.length });
      }
      if (url.pathname === '/test' && req.method === 'POST') {
        const n = await pushAll(env, { title: 'Avio.AI', body: 'Notifications are on. Case emails will show up like this.', id: '' });
        return json({ ok: true, sent: n });
      }
      if (url.pathname === '/poll' && req.method === 'POST') return json(await poll(env));
      return json({ error: 'not found' }, 404);
    } catch (e) {
      return json({ error: String(e && e.message || e) }, 500);
    }
  },
  async scheduled(evt, env, ctx) { ctx.waitUntil(poll(env).catch(async e => env.MAIL.put('err', String(e.message || e)))); }
};

// ───────── mailboxes: [{id, kind: 'google'|'microsoft', email}] in KV 'boxes'; per mailbox rt:<id>, last:<id>, err:<id>
export async function boxes(env) {
  const B = await getJ(env, 'boxes', null); if (B) return B;
  const rt = await env.MAIL.get('rt'); if (!rt) return [];        // a watcher set up before several mailboxes: move its one Gmail over
  const email = (await env.MAIL.get('acct')) || '', id = await boxId('google', email);
  await env.MAIL.put('rt:' + id, rt); const l = await env.MAIL.get('last'); if (l) await env.MAIL.put('last:' + id, l);
  const out = [{ id, kind: 'google', email, at: Date.now() }];
  await env.MAIL.put('boxes', JSON.stringify(out));
  for (const k of ['rt', 'acct', 'last']) await env.MAIL.delete(k);
  return out;
}
const boxId = async (kind, email) => kind[0] + (await sh(kind + ':' + String(email).toLowerCase())).slice(0, 10);
async function addBox(env, kind, email, rt) {
  const id = await boxId(kind, email), B = (await boxes(env)).filter(b => b.id !== id);
  B.push({ id, kind, email, at: Date.now() });
  await env.MAIL.put('rt:' + id, rt);
  if (!(await env.MAIL.get('last:' + id))) await env.MAIL.put('last:' + id, String(Math.floor(Date.now() / 1000) - 3600));   // start with the last hour
  await env.MAIL.delete('err:' + id);
  await env.MAIL.put('boxes', JSON.stringify(B));
  return id;
}

// ───────── poll every mailbox
export async function poll(env, deps = {}) {
  const f = deps.fetch || fetch;
  const B = await boxes(env); if (!B.length) return { ok: false, reason: 'No mailbox connected' };
  const X = { env, f, cfg: await getCfg(env), seen: new Set(await getJ(env, 'seen', [])), threads: new Set(await getJ(env, 'threads', [])) };
  let checked = 0, saved = 0; const errors = [];
  for (const b of B) {
    try {
      const r = b.kind === 'microsoft' ? await pollMs(X, b) : await pollGoogle(X, b);
      checked += r.checked; saved += r.saved; await env.MAIL.delete('err:' + b.id);
    } catch (e) { const m = String(e && e.message || e); errors.push(`${b.email}: ${m}`); await env.MAIL.put('err:' + b.id, m); }
  }
  await env.MAIL.put('seen', JSON.stringify([...X.seen].slice(-3000)));
  await env.MAIL.put('threads', JSON.stringify([...X.threads].slice(-800)));
  if (errors.length) await env.MAIL.put('err', errors.join(' · ')); else await env.MAIL.delete('err');
  return { ok: errors.length < B.length, checked, saved, errors };
}
function belongs(X, b, from, subject, thread) {
  const mine = from === String(b.email).toLowerCase();
  const tag = (subject.match(TAG_RX) || [])[1] || '';
  const ticket = X.cfg.tickets.find(t => subject.includes(t)) || '';
  const watched = !mine && X.cfg.senders.some(s => s.startsWith('@') ? from.endsWith(s) : from === s);
  return !!(tag || ticket || X.threads.has(thread) || watched);
}
async function filed(X, item) {
  X.threads.add(item.threadId);
  if (!item.mine) await pushAll(X.env, { title: `${item.fromName || item.from}${item.tag ? ' · ' + item.tag.split('-')[0] : ''}`, body: item.subject || '(no subject)', id: item.id }, X.f);
}

// ───────── Gmail
async function pollGoogle(X, b) {
  const { env, f } = X;
  const rt = await env.MAIL.get('rt:' + b.id); if (!rt) throw new Error('Sign in again');
  const tok = await googleToken(env, { refresh_token: rt, grant_type: 'refresh_token' }, f);
  const H = { Authorization: 'Bearer ' + tok.access_token };
  const last = +(await env.MAIL.get('last:' + b.id) || 0) || Math.floor(Date.now() / 1000) - 3600;
  const startedAt = Math.floor(Date.now() / 1000);
  const list = await (await f(`${GMAIL}/messages?maxResults=50&q=${encodeURIComponent(`after:${last - 300} -in:chats`)}`, { headers: H })).json();
  if (list.error) throw new Error('Gmail: ' + (list.error.message || list.error.status));
  let saved = 0; const ids = (list.messages || []).map(m => m.id).filter(id => !X.seen.has(id)).reverse();
  for (const id of ids) {
    const meta = await (await f(`${GMAIL}/messages/${id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject`, { headers: H })).json();
    const hd = hdrs(meta.payload);
    X.seen.add(id);
    if (!belongs(X, b, addr(hd.from), hd.subject || '', meta.threadId)) continue;
    await filed(X, await captureGoogle(X, H, id, b));
    saved++;
  }
  await env.MAIL.put('last:' + b.id, String(startedAt));
  return { checked: ids.length, saved };
}

async function captureGoogle(X, H, id, b) {
  const { env, f } = X;
  const m = await (await f(`${GMAIL}/messages/${id}?format=full`, { headers: H })).json();
  const hd = hdrs(m.payload);
  const parts = flat(m.payload);
  const plain = parts.find(p => p.mimeType === 'text/plain' && p.body && p.body.data && !p.filename);
  const htmlP = parts.find(p => p.mimeType === 'text/html' && p.body && p.body.data && !p.filename);
  const full = plain ? b64uText(plain.body.data) : htmlP ? htmlText(b64uText(htmlP.body.data)) : (m.snippet || '');
  const text = stripQuoted(full);
  const from = addr(hd.from);
  const item = { v: 1, id: m.id, threadId: m.threadId, box: b.email, from, fromName: name(hd.from), to: hd.to || '', cc: hd.cc || '', subject: hd.subject || '',
    date: +m.internalDate || Date.now(), tag: ((hd.subject || '').match(TAG_RX) || [])[1] || '', tickets: tickets(hd.subject || ''),
    mine: from === String(b.email).toLowerCase(), text: text.slice(0, MAX_TEXT), quoted: full.length > text.length ? full.slice(text.length, text.length + 8000) : '', attachments: [], at: Date.now() };
  let i = 0;
  for (const p of parts.filter(p => p.filename && p.body && (p.body.attachmentId || p.body.data))) {
    const a = { name: p.filename, mime: p.mimeType || 'application/octet-stream', size: p.body.size || 0 };
    if (a.size > MAX_ATT) { a.skipped = 'too large'; item.attachments.push(a); continue; }
    let data = p.body.data;
    if (!data) data = (await (await f(`${GMAIL}/messages/${id}/attachments/${p.body.attachmentId}`, { headers: H })).json()).data;
    a.path = `inbox/files/${m.id}-${i++}-${safeName(p.filename)}`;
    await ghPut(env, f, a.path, b64uToStd(data), `inbox attachment ${p.filename}`);
    item.attachments.push(a);
  }
  await ghPut(env, f, `inbox/${m.id}.json`, utf8b64(JSON.stringify(item, null, 1)), `inbox: ${item.fromName || item.from} · ${item.subject}`.slice(0, 120));
  return item;
}

// ───────── Microsoft 365 / Outlook (Microsoft Graph)
async function msToken(env, f, b) {
  const rt = await env.MAIL.get('rt:' + b.id); if (!rt) throw new Error('Sign in again');
  const r = await f(msAuth(env) + '/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: env.MS_CLIENT_ID || '', grant_type: 'refresh_token', refresh_token: rt, scope: MS_SCOPE }) });
  const j = await r.json(); if (!r.ok) throw new Error('Microsoft sign-in: ' + String(j.error_description || j.error || r.status).split('\r')[0]);
  if (j.refresh_token && j.refresh_token !== rt) await env.MAIL.put('rt:' + b.id, j.refresh_token);   // Microsoft hands out a new one each time
  return j.access_token;
}
async function pollMs(X, b) {
  const { env, f } = X;
  const H = { Authorization: 'Bearer ' + await msToken(env, f, b) };
  const last = +(await env.MAIL.get('last:' + b.id) || 0) || Math.floor(Date.now() / 1000) - 3600;
  const startedAt = Math.floor(Date.now() / 1000);
  const since = new Date((last - 300) * 1000).toISOString().replace(/\.\d+Z$/, 'Z');
  let next = `${GRAPH}/messages?$filter=${encodeURIComponent(`receivedDateTime ge ${since} and isDraft eq false`)}&$orderby=receivedDateTime%20asc&$top=50&$select=id,subject,from,conversationId,internetMessageId,receivedDateTime`;
  let checked = 0, saved = 0;
  for (let page = 0; next && page < 4; page++) {
    const list = await (await f(next, { headers: H })).json();
    if (list.error) throw new Error('Outlook: ' + (list.error.message || list.error.code));
    for (const m of list.value || []) {
      const key = 'o' + (await sh(m.internetMessageId || m.id)).slice(0, 22);   // the Graph id changes when a message is moved; this does not
      if (X.seen.has(key)) continue;
      X.seen.add(key); checked++;
      const thread = 'o' + (await sh(m.conversationId || key)).slice(0, 22);
      const from = String((m.from && m.from.emailAddress && m.from.emailAddress.address) || '').toLowerCase();
      if (!belongs(X, b, from, m.subject || '', thread)) continue;
      await filed(X, await captureMs(X, H, m, key, thread, b));
      saved++;
    }
    next = list['@odata.nextLink'] || '';
  }
  await env.MAIL.put('last:' + b.id, String(startedAt));
  return { checked, saved };
}
async function captureMs(X, H, m, key, thread, b) {
  const { env, f } = X, mid = encodeURIComponent(m.id);
  const d = await (await f(`${GRAPH}/messages/${mid}?$select=subject,from,toRecipients,ccRecipients,receivedDateTime,body,uniqueBody,hasAttachments`, { headers: { ...H, Prefer: 'outlook.body-content-type="text"' } })).json();
  if (d.error) throw new Error('Outlook: ' + (d.error.message || d.error.code));
  const full = String((d.body && d.body.content) || '').replace(/\r/g, ''), uniq = String((d.uniqueBody && d.uniqueBody.content) || '').replace(/\r/g, '');
  const text = stripQuoted(uniq || full);
  const ea = x => (x && x.emailAddress) || {}, who = x => ea(x).name && ea(x).name !== ea(x).address ? `${ea(x).name} <${ea(x).address}>` : (ea(x).address || '');
  const from = String(ea(d.from).address || '').toLowerCase(), subject = d.subject || '';
  const rest = uniq && full.length > uniq.length ? full.slice(uniq.length) : full.length > text.length ? full.slice(text.length) : '';
  const item = { v: 1, id: key, threadId: thread, box: b.email, from, fromName: ea(d.from).name || from, to: (d.toRecipients || []).map(who).join(', '), cc: (d.ccRecipients || []).map(who).join(', '), subject,
    date: Date.parse(d.receivedDateTime || m.receivedDateTime) || Date.now(), tag: (subject.match(TAG_RX) || [])[1] || '', tickets: tickets(subject),
    mine: from === String(b.email).toLowerCase(), text: text.slice(0, MAX_TEXT), quoted: rest.trim().slice(0, 8000), attachments: [], at: Date.now() };
  if (d.hasAttachments) {
    const L = await (await f(`${GRAPH}/messages/${mid}/attachments?$select=id,name,contentType,size,isInline`, { headers: H })).json();
    let i = 0;
    for (const x of L.value || []) {
      const a = { name: x.name || 'attachment', mime: x.contentType || 'application/octet-stream', size: x.size || 0 };
      if (x['@odata.type'] !== '#microsoft.graph.fileAttachment') { a.skipped = 'not a file'; item.attachments.push(a); continue; }
      if (x.isInline && /^image\//.test(a.mime) && a.size < 30000) continue;   // logos in signatures
      if (a.size > MAX_ATT) { a.skipped = 'too large'; item.attachments.push(a); continue; }
      const r = await f(`${GRAPH}/messages/${mid}/attachments/${encodeURIComponent(x.id)}/$value`, { headers: H });
      if (!r.ok) { a.skipped = 'could not be read'; item.attachments.push(a); continue; }
      a.path = `inbox/files/${key}-${i++}-${safeName(a.name)}`;
      await ghPut(env, f, a.path, bytesB64(new Uint8Array(await r.arrayBuffer())), `inbox attachment ${a.name}`);
      item.attachments.push(a);
    }
  }
  await ghPut(env, f, `inbox/${key}.json`, utf8b64(JSON.stringify(item, null, 1)), `inbox: ${item.fromName || item.from} · ${subject}`.slice(0, 120));
  return item;
}

// ───────── helpers: Gmail, GitHub, KV
async function googleToken(env, params, f = fetch) {
  const r = await f('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, ...params }) });
  const j = await r.json(); if (!r.ok) throw new Error('Google sign-in: ' + (j.error_description || j.error || r.status)); return j;
}
async function ghPut(env, f, path, b64, message) {
  const u = `https://api.github.com/repos/${env.CASES_REPO}/contents/${path}`;
  const h = { Authorization: 'Bearer ' + env.GITHUB_TOKEN, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'avio-mail' };
  let sha; const g = await f(u, { headers: h }); if (g.ok) sha = (await g.json()).sha;
  const r = await f(u, { method: 'PUT', headers: { ...h, 'content-type': 'application/json' }, body: JSON.stringify({ message, content: b64, ...(sha ? { sha } : {}) }) });
  if (!r.ok) throw new Error(`Cases repo ${r.status} writing ${path}`);
}
const getJ = async (env, k, d) => { try { return JSON.parse(await env.MAIL.get(k)) ?? d } catch (e) { return d } };
const getCfg = async env => ({ senders: [], tickets: [], ...(await getJ(env, 'cfg', {})) });
const hdrs = p => Object.fromEntries(((p && p.headers) || []).map(h => [h.name.toLowerCase(), h.value]));
const addr = s => ((String(s || '').match(/<([^>]+)>/) || [])[1] || String(s || '')).trim().toLowerCase();
const name = s => (String(s || '').replace(/<[^>]*>/, '').replace(/"/g, '').trim()) || addr(s);
const safeName = s => String(s).replace(/[^\w.\-]+/g, '_').slice(-80);
async function sh(s) { return b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', enc(String(s))))); }
const flat = p => p ? [p, ...(p.parts || []).flatMap(flat)] : [];
export function tickets(subject) {
  const out = new Set(); const s = String(subject).replace(TAG_RX, ' ');
  for (const m of s.matchAll(/\b(?:ticket|case|sr|ref(?:erence)?|tkt|incident|req(?:uest)?|inc)\s*(?:no\.?|number|nr\.?|#|:)?\s*#?\s*([A-Z]{0,5}-?\d{4,}[A-Z0-9-]*)/gi)) out.add(m[1]);
  for (const m of s.matchAll(/#\s?([A-Z]{0,5}-?\d{4,}[A-Z0-9-]*)/gi)) out.add(m[1]);
  for (const m of s.matchAll(/\b([A-Z]{2,5}-\d{4,})\b/g)) out.add(m[1]);
  const L = [...out].filter(t => !t.startsWith('-'));
  return L.filter(t => !L.some(o => o !== t && o.endsWith(t)));
}
export function stripQuoted(t) {
  const L = String(t).replace(/\r/g, '').split('\n'); const out = [];
  for (const l of L) {
    if (/^\s*On .{5,200}wrote:\s*$/.test(l) || /^\s*-{2,}\s*Original Message\s*-{2,}/i.test(l) || /^\s*_{10,}\s*$/.test(l)) break;
    if (/^\s*From:\s.+/i.test(l) && out.length > 2 && L.slice(L.indexOf(l), L.indexOf(l) + 5).some(x => /^\s*(Sent|Date|To|Subject):/i.test(x))) break;
    if (/^\s*>/.test(l)) continue;
    out.push(l);
  }
  return out.join('\n').replace(/\n{3,}/g, '\n\n').trim();
}
const htmlText = h => String(h).replace(/<(style|script)[\s\S]*?<\/\1>/gi, '').replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|tr|li|h\d)>/gi, '\n').replace(/<[^>]+>/g, '')
  .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/[ \t]+\n/g, '\n');
const b64uToStd = s => String(s).replace(/-/g, '+').replace(/_/g, '/');
const b64uBytes = s => { const b = atob(b64uToStd(s) + '==='.slice((s.length + 3) % 4)); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
const b64uText = s => new TextDecoder().decode(b64uBytes(s));
const bytesB64 = u => { let s = ''; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); };
const b64u = u => bytesB64(u).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const utf8b64 = s => bytesB64(new TextEncoder().encode(s));
const enc = s => new TextEncoder().encode(s);
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const html = (body, status = 200) => new Response(`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font:17px system-ui;padding:24px;line-height:1.5">${body}</body>`, { status, headers: { 'content-type': 'text/html; charset=utf-8' } });
async function hmac(key, msg) { const k = await crypto.subtle.importKey('raw', enc(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); return b64u(new Uint8Array(await crypto.subtle.sign('HMAC', k, enc(msg)))).slice(0, 32); }

// ───────── Web Push (RFC 8291 aes128gcm payload, RFC 8292 VAPID); keys are made once and kept in KV
export async function vapidKeys(env) {
  let v = await getJ(env, 'vapid', null);
  if (!v) {
    const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    v = { jwk: await crypto.subtle.exportKey('jwk', k.privateKey), pub: b64u(new Uint8Array(await crypto.subtle.exportKey('raw', k.publicKey))) };
    await env.MAIL.put('vapid', JSON.stringify(v));
  }
  return v;
}
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
export async function encryptPayload(sub, payload) {
  const uaPub = b64uBytes(sub.keys.p256dh), auth = b64uBytes(sub.keys.auth);
  const as = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, as.privateKey, 256));
  const ikm = await hkdf(auth, ecdh, cat(enc('WebPush: info\0'), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, cat(enc(payload), new Uint8Array([2]))));
  const hdr = new Uint8Array(21 + 65); hdr.set(salt, 0); new DataView(hdr.buffer).setUint32(16, 4096); hdr[20] = 65; hdr.set(asPub, 21);
  return cat(hdr, ct);
}
export async function vapidAuth(env, endpoint) {
  const v = await vapidKeys(env);
  const key = await crypto.subtle.importKey('jwk', v.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const h = b64u(enc(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const p = b64u(enc(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT || 'mailto:notifications@example.com' })));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc(h + '.' + p)));
  return `vapid t=${h}.${p}.${b64u(sig)}, k=${v.pub}`;
}
async function pushAll(env, msg, f = fetch) {
  const subs = await getJ(env, 'subs', []); const keep = []; let sent = 0;
  for (const s of subs) {
    try {
      const r = await f(s.endpoint, { method: 'POST', headers: { Authorization: await vapidAuth(env, s.endpoint), 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '86400', Urgency: 'high' }, body: await encryptPayload(s, JSON.stringify(msg)) });
      if (r.status === 404 || r.status === 410) continue;   // the phone dropped this subscription
      if (r.ok) sent++;
    } catch (e) { }
    keep.push(s);
  }
  if (keep.length !== subs.length) await env.MAIL.put('subs', JSON.stringify(keep));
  return sent;
}
