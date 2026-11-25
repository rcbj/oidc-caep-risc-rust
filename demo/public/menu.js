// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// The top bar's user menu is a <details>: it opens and closes with no script.
// This only closes it the way a menu closes: a click outside it, or Escape.
// Its own scope: every page script shares one global scope, and two
// top-level declarations of one name (app.js and pep.js both had `panel`)
// make the second script fail to load at all.
(() => {
const menu = document.querySelector('.acct-menu');
if (menu) {
  document.addEventListener('click', (e) => { if (menu.open && !menu.contains(e.target)) menu.open = false; });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && menu.open) {
      menu.open = false;
      menu.querySelector('summary')?.focus();
    }
  });
}
})();
