// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// The Policy enforcement tab: fetches the server-drawn fragment again every
// two seconds, so the counters and the times (last update, next pull) stay
// current, keeping closed any pane the person closed. The server escapes
// everything in it. A hidden page doesn't poll;
// a 401 means the session is gone, so it goes back to the sign-in page.
// Its own scope: every page script shares one global scope, and two
// top-level declarations of one name (app.js and pep.js both had `panel`)
// make the second script fail to load at all.
(() => {
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
    if (answer.ok) {
      // The panes are collapsible: keep closed the ones the person closed.
      const closed = new Set([...panel.querySelectorAll('details[id]')].filter((d) => !d.open).map((d) => d.id));
      panel.innerHTML = await answer.text();
      for (const id of closed) {
        const pane = document.getElementById(id);
        if (pane) pane.open = false;
      }
      // The Collapse all / Expand all toggle reads the panes again.
      document.dispatchEvent(new Event('panes-redrawn'));
    }
  } catch (err) {
    // The demo restarting: keep what is shown and try again on the next tick.
  }
}

if (panel) {
  setInterval(refresh, EVERY_MS);
  document.addEventListener('visibilitychange', refresh);
}
})();
