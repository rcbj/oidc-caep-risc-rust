// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// The signed-in page's one script. It shows the Shared Signals events about THIS session, live:
//
//   - an EventSource on /events receives each event as JSON the moment the server's receiver has it,
//     and the ones a reconnecting tab missed (the server replays from the Last-Event-ID the browser sends);
//   - if the event stream cannot be kept open, it polls GET /api/signals?after=<id> every few seconds;
//   - each event is drawn into the log (on the events tab), counted on the tab's label, and announced
//     with a notice on the other tab; nothing reloads the page;
//   - `signed-out` (or a 401 from the API) means the session is already gone on the server: say why and
//     go back to the sign-in page.
//
// The page is ONE account's (its URL is /u/<account>/, in data-base): the event stream, the API and every
// link here are that account's, and the server only ever sends them events about that account's session
// or person, so nothing here filters. Another account in the same browser has its own tabs and streams.
// Everything an event carries is identity provider data and is drawn with textContent, never as HTML.

const panel = document.getElementById('panel');
const log = document.getElementById('log');
const logEmpty = document.getElementById('log-empty');
const count = document.getElementById('signal-count');
const toast = document.getElementById('signal-toast');
const banner = document.getElementById('signal-banner');
const liveState = document.getElementById('live-state');
const streamStatus = document.getElementById('stream-status');
const onEventsTab = panel?.dataset.tab === 'events';
const base = panel?.dataset.base || '';
let lastId = Number(panel?.dataset.lastId || 0);
let total = Number(count?.textContent || 0);
let events;
let pollTimer;

const shortType = (uri) => String(uri).replace(/^.*\/event-type\//, '');
const setLive = (text) => { if (liveState) liveState.textContent = text; };

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  for (const c of children) node.append(c);
  return node;
}

function memberText(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') {
    const values = Object.values(value);
    return values.length && values.every((v) => typeof v === 'string') ? values.join(' / ') : JSON.stringify(value);
  }
  return String(value);
}

/** One log entry, the same markup the server draws. */
function entryNode(e) {
  const outcome = e.about === 'stream' ? 'about the stream: the verification this session asked for'
    : e.ended ? 'ended this session' : 'recorded; this session continues';
  const item = el('li', { class: 'log-item fresh', 'data-id': String(e.id) },
    el('div', { class: 'log-top' },
      el('span', { class: `badge ${e.family.toLowerCase()}` }, e.family), ' ',
      el('strong', {}, shortType(e.type)), ' ',
      el('time', {}, e.at)),
    el('p', { class: `log-outcome${e.ended ? ' ended' : ''}` }, outcome));
  if (e.subject) item.append(el('p', {}, el('small', {}, `Subject: ${e.subject}`)));
  const rows = Object.entries(e.members || {}).filter(([k]) => k !== 'subject');
  if (rows.length) {
    const table = el('table', { class: 'facts members' });
    for (const [k, v] of rows) table.append(el('tr', {}, el('th', {}, k), el('td', {}, memberText(v))));
    item.append(table);
  }
  item.append(el('p', {}, el('small', {}, `jti ${e.jti}`)));
  return item;
}

function receive(e) {
  if (!e || typeof e.id !== 'number' || e.id <= lastId) return; // already shown
  lastId = e.id;
  total += 1;
  if (count) count.textContent = String(total);
  if (log && onEventsTab) {
    log.prepend(entryNode(e));
    if (logEmpty) logEmpty.hidden = true;
  } else if (toast) {
    toast.replaceChildren(`New ${e.family} event: ${shortType(e.type)}. `, el('a', { href: `${base}/?tab=events` }, 'See it'));
    toast.hidden = false;
  }
}

function signedOut(type, reason) {
  if (events) events.close();
  clearTimeout(pollTimer);
  if (banner) {
    banner.textContent = type
      ? `You were signed out: the identity provider sent ${type}${reason ? ` (${memberText(reason)})` : ''}.`
      : 'Your session has ended.';
    banner.hidden = false;
  }
  setLive('signed out');
  setTimeout(() => { location.href = '/'; }, 4000);
}

// The fallback: ask the API for what arrived after the last event shown.
async function poll() {
  try {
    const r = await fetch(`${base}/api/signals?after=${lastId}`, { headers: { accept: 'application/json' }, credentials: 'same-origin' });
    if (r.status === 401) return signedOut();
    const body = await r.json();
    for (const e of body.events) receive(e);
    if (body.streamStatus && streamStatus) streamStatus.textContent = `${body.streamStatus.status} (${body.streamStatus.at})`;
    setLive('live (polling every 3 s)');
  } catch {
    setLive('reconnecting…');
  }
  pollTimer = setTimeout(poll, 3000);
}

function listen() {
  if (!('EventSource' in window)) return poll();
  events = new EventSource(`${base}/events?after=${lastId}`);
  events.addEventListener('open', () => setLive('live'));
  events.addEventListener('signal', (m) => receive(JSON.parse(m.data)));
  events.addEventListener('stream', (m) => {
    const s = JSON.parse(m.data);
    if (streamStatus) streamStatus.textContent = `${s.status} (${s.at})`;
  });
  events.addEventListener('signed-out', (m) => {
    const { type, reason } = JSON.parse(m.data);
    signedOut(type, reason);
  });
  // This account was signed in again (another tab, the same person): its page is a new session's now.
  events.addEventListener('replaced', () => { location.reload(); });
  events.addEventListener('error', () => {
    // The browser reconnects by itself (and is replayed what it missed). Only if it gave up, poll instead.
    setLive('reconnecting…');
    if (events.readyState === EventSource.CLOSED) poll();
  });
}

// The verification request without leaving the page; the form still works without this script.
document.getElementById('verify-form')?.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const button = ev.target.querySelector('button');
  button.disabled = true;
  try {
    const r = await fetch(`${base}/signals/verify`, { method: 'POST', headers: { accept: 'application/json' }, credentials: 'same-origin' });
    const { outcome } = await r.json();
    setLive(outcome === 'sent' ? 'live — verification requested' : 'live — the verification request was refused');
  } finally {
    button.disabled = false;
  }
});

listen();
