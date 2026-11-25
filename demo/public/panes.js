// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// The Collapse all / Expand all toggle of the Session and Policy enforcement
// tabs. It acts on the panes of the tab shown (the <details> in #panel) and
// nothing else. It is hidden until this script runs: without a script every
// pane still opens and closes by itself. Its label says what it will do:
// Collapse all while any pane is open, Expand all once they are all closed.
// Its own scope: every page script shares one global scope, and two
// top-level declarations of one name (app.js and pep.js both had `panel`)
// make the second script fail to load at all.
(() => {
const toggle = document.getElementById('panes-toggle');
const panel = document.getElementById('panel');

const panes = () => [...(panel?.querySelectorAll('details.pane') || [])];

function label() {
  const list = panes();
  toggle.hidden = list.length === 0;
  const anyOpen = list.some((d) => d.open);
  toggle.textContent = anyOpen ? 'Collapse all' : 'Expand all';
  toggle.setAttribute('aria-expanded', String(anyOpen));
}

if (toggle && panel) {
  toggle.addEventListener('click', () => {
    const open = !panes().some((d) => d.open);
    for (const d of panes()) d.open = open;
    label();
  });
  // A pane opened or closed by hand; `toggle` does not bubble, so capture it.
  panel.addEventListener('toggle', label, true);
  // The Policy enforcement tab redraws its panes every two seconds.
  document.addEventListener('panes-redrawn', label);
  label();
}
})();
