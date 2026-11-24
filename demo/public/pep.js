// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// The Policy enforcement tab: fetches the server-drawn fragment again every
// two seconds, so the counters and the times (last update, next pull) stay
// current. The server escapes everything in it. A hidden page doesn't poll;
// a 401 means the session is gone, so it goes back to the sign-in page.
const panel = document.getElementById('pep-panel');
const EVERY_MS = 2000;

async function refresh() {
  if (!panel || document.hidden) return;
  try {
    const answer = await fetch('/pep-status.html', { credentials: 'same-origin', cache: 'no-store' });
    if (answer.status === 401) {
      window.location.assign('/');
      return;
    }
    if (answer.ok) panel.innerHTML = await answer.text();
  } catch (err) {
    // The demo restarting: keep what is shown and try again on the next tick.
  }
}

if (panel) {
  setInterval(refresh, EVERY_MS);
  document.addEventListener('visibilitychange', refresh);
}
