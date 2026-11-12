// Run: node tests/homepage.test.cjs
const assert = require('node:assert/strict');
const { readFileSync, existsSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const root = join(__dirname, '..');
const html = readFileSync(join(root, 'index.html'), 'utf8').replace(/<!--[\s\S]*?-->/g, '');

// Catch broken local resource paths and fragment links, including responsive variants.
const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
assert.equal(new Set(ids).size, ids.length, 'Duplicate IDs');
for (const [, value] of html.matchAll(/\b(?:src|href)="([^"]+)"/g)) {
   if (/^(?:https?:|\/\/|mailto:|tel:)/.test(value)) continue;
   if (value.startsWith('#')) assert.ok(ids.includes(value.slice(1)), value);
   else assert.ok(existsSync(join(root, value.split('?')[0])), value);
}
for (const [, list] of html.matchAll(/\bsrcset="([^"]+)"/g)) {
   for (const item of list.split(',')) assert.ok(existsSync(join(root, item.trim().split(' ')[0])), item);
}

function target(extra = {}) {
   return Object.assign({
      attrs: {}, handlers: {},
      addEventListener(type, handler) { this.handlers[type] = handler; },
      setAttribute(key, value) { this.attrs[key] = value; },
      getAttribute(key) { return this.attrs[key]; },
      focus() { this.focused = true; }
   }, extra);
}
const button = target();
button.setAttribute('aria-expanded', 'false');
const dialog = target({
   showModal() { this.open = true; }, close() { this.open = false; },
   getBoundingClientRect: () => ({ left: 10, top: 10, right: 100, bottom: 100 })
});
const photo = target({ dataset: { dialog: 'modal-01' } });
const media = target({ matches: false });
const nav = { toggleClass(key, value) { this[key] = value; }, on(type, handler) { this[type] = handler; } };
const links = { on(type, handler) { this[type] = handler; } };
const sections = { waypoint() {} };
function $(selector) {
   if (selector === '#nav-wrap') return nav;
   if (selector === '#nav a') return links;
   if (selector === 'header#home, main > section') return sections;
   return { ready(callback) { callback($); }, on() {} };
}
$.fx = {};
vm.runInNewContext(readFileSync(join(root, 'js/init.js'), 'utf8'), {
   jQuery: $, matchMedia: query => query.includes('reduced-motion') ? media : target(), window: {}, HTMLDialogElement: function () {},
   document: {
      documentElement: { classList: { add() {} } },
      querySelector: () => button, getElementById: () => dialog,
      querySelectorAll: selector => selector.startsWith('.item-wrap') ? [photo] : [dialog]
   }
});
button.handlers.click();
assert.equal(button.getAttribute('aria-expanded'), 'true');
assert.equal(nav['menu-open'], true);
nav.keydown({ key: 'Escape' });
assert.equal(button.getAttribute('aria-expanded'), 'false');
assert.equal(button.focused, true);
button.handlers.click();
links.click();
assert.equal(nav['menu-open'], false, 'Following a link closes the menu');
let prevented = false;
photo.handlers.click({ preventDefault() { prevented = true; } });
assert.ok(prevented && dialog.open, 'Normal photo click opens the dialog');
dialog.close();
photo.handlers.click({ ctrlKey: true, preventDefault() { assert.fail('Modified click must keep the original link'); } });
assert.equal(dialog.open, false);
dialog.showModal();
dialog.handlers.pointerdown({ clientX: 50, clientY: 50 });
dialog.handlers.pointerup({ clientX: 0, clientY: 0 });
assert.equal(dialog.open, true, 'Dragging from inside onto backdrop must not dismiss');
dialog.handlers.pointerdown({ clientX: 0, clientY: 0 });
dialog.handlers.pointerup({ clientX: 0, clientY: 0 });
assert.equal(dialog.open, false, 'Clicking outside dismisses on browsers without closedby');
media.matches = true;
media.handlers.change();
assert.equal($.fx.off, true, 'Reduced motion disables jQuery fades');
console.log('Homepage resources, menu, photo dialogs and reduced motion: OK');
