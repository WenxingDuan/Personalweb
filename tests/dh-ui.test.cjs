'use strict';

// Real DH source and WebCrypto; only the DOM, clock scheduling and result delivery are controlled.
const test = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const source = readFileSync(join(__dirname, '../js/dh.js'), 'utf8');
const html = readFileSync(join(__dirname, '../DH.html'), 'utf8');
const sensitive = ['myPub', 'peerPub', 'fingerprint', 'plain', 'cipher'];
const actionButtons = ['genBtn', 'copyMyPub', 'buildSessionBtn', 'confirmBtn', 'mismatchBtn', 'encryptBtn', 'decryptBtn', 'copyCipher'];

function target(properties = {}) {
  const handlers = new Map();
  return Object.assign({
    addEventListener(type, handler) {
      if (!handlers.has(type)) handlers.set(type, []);
      handlers.get(type).push(handler);
    },
    async fire(type, event = {}) {
      await Promise.all((handlers.get(type) || []).map(handler => handler(event)));
    }
  }, properties);
}

async function until(predicate) {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('Timed out waiting for UI/crypto completion');
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  await new Promise(setImmediate);
}

function page(options = {}) {
  const els = Object.fromEntries([...html.matchAll(/<[^>]+data-id="([^"]+)"[^>]*>/g)].map(([tag, id]) => [id, target({
    dataset: { id }, value: options.restored && sensitive.includes(id) ? 'restored secret' : '',
    checked: id === 'verifyCheck' && !!options.restored, disabled: /\bdisabled\b/.test(tag),
    textContent: '', className: '', hidden: false
  })]));
  const warning = { hidden: true };
  const document = target({ hidden: false,
    querySelectorAll: () => Object.values(els), getElementById: id => id === 'compat-warning' ? warning : els[id]
  });
  const window = target({ location: new URL(options.url || 'https://secure.example/DH.html'),
    isSecureContext: options.secure !== false });
  window.self = window; window.top = options.framed ? {} : window;
  const navigator = { clipboard: { writeText: async () => {} } };
  const timers = new Map(), hooks = new Map();
  let pending = 0, timerId = 0;
  const subtle = new Proxy(webcrypto.subtle, { get(real, method) {
    if (typeof real[method] !== 'function') return real[method];
    return async (...args) => {
      const hook = hooks.get(method);
      if (hook) hooks.delete(method);
      pending++;
      try {
        const value = await real[method](...args);
        return hook ? await hook(value) : value;
      } finally { pending--; }
    };
  } });
  const context = vm.createContext({ module: { exports: {} }, TextEncoder, TextDecoder, URL, Date, performance,
    crypto: options.noCrypto ? undefined : { subtle, getRandomValues: webcrypto.getRandomValues.bind(webcrypto) },
    document, window, navigator, atob, btoa, DOMException,
    setTimeout(callback) { timers.set(++timerId, callback); return timerId; },
    clearTimeout(id) { timers.delete(id); }
  });
  vm.runInContext(source, context, { filename: 'js/dh.js' });
  const { DH, setupPage } = context.module.exports;
  const result = {
    els, warning, document, window, navigator, timers, DH, hooks,
    start: setupPage,
    ready: () => until(() => !els.genBtn.disabled || !warning.hidden),
    idle: () => until(() => pending === 0),
    click: id => els[id].fire('click'),
    async peer(text) { els.peerPub.value = text; await els.peerPub.fire('input'); },
    hold(method, fail = false) {
      let release, entered;
      const wait = new Promise(resolve => { release = resolve; });
      const started = new Promise(resolve => { entered = resolve; });
      hooks.set(method, async value => {
        entered(); await wait;
        if (fail) throw new Error('Injected delayed failure');
        return value;
      });
      return { started, release };
    },
    snapshot: () => Object.fromEntries(Object.entries(els).map(([id, e]) => [id,
      [e.value, e.checked, e.disabled, e.textContent, e.className]])),
    dispose: () => els.resetBtn.fire('click')
  };
  if (!options.manualStart) setupPage();
  return result;
}

function cleared(p) {
  for (const id of sensitive) assert.equal(p.els[id].value, '', id);
  assert.equal(p.els.verifyCheck.checked, false);
  assert.equal(p.els.encryptBtn.disabled, true);
  assert.equal(p.els.decryptBtn.disabled, true);
  assert.equal(p.els.resetBtn.disabled, false);
  assert.equal(p.timers.size, 0);
}

async function establish(p, confirm = true) {
  await p.click('genBtn');
  const remote = await p.DH.createOffer();
  const peerSession = await remote.establish(p.els.myPub.value);
  await p.peer(remote.text);
  await p.click('buildSessionBtn');
  assert.equal(p.els.fingerprint.value.replace(/ /g, ''), peerSession.safetyCode);
  if (confirm) {
    p.els.verifyCheck.checked = true;
    await p.els.verifyCheck.fire('change');
    await p.click('confirmBtn');
    peerSession.confirm();
  }
  remote.destroy();
  return peerSession;
}

test('initialization clears restored fields and confirmation before crypto probing', async () => {
  const p = page({ restored: true });
  cleared(p);
  assert.equal(p.els.genBtn.disabled, true);
  await p.ready();
  assert.equal(p.warning.hidden, true);
  assert.equal(p.els.genBtn.disabled, false);
  await p.dispose();
});

test('unsupported origins, insecure contexts, missing crypto and framing stay disabled', async () => {
  for (const options of [{ url: 'file:///DH.html' }, { url: 'http://example.com/DH.html' },
    { secure: false }, { noCrypto: true }, { framed: true }]) {
    const p = page(options);
    assert.equal(p.warning.hidden, false);
    for (const id of actionButtons) assert.equal(p.els[id].disabled, true, id);
    await p.click('genBtn');
    cleared(p);
    await p.dispose();
  }
});

test('each failed crypto capability probe leaves actions disabled with an explanation', async () => {
  for (const method of ['generateKey', 'deriveBits', 'deriveKey', 'encrypt', 'decrypt']) {
    const p = page({ manualStart: true });
    p.hooks.set(method, () => { throw new Error('Unavailable test capability'); });
    p.start(); await p.ready();
    assert.equal(p.warning.hidden, false);
    assert.match(p.els.status.textContent, /capabilities are unavailable/i);
    for (const id of actionButtons) assert.equal(p.els[id].disabled, true, `${method}: ${id}`);
    await p.dispose();
  }
});

test('verification gates handlers, enables messaging, and mismatch clears the session', async () => {
  const p = page(); await p.ready();
  const remote = await establish(p, false);
  assert.match(p.els.fingerprint.value, /^[a-f0-9]{8}( [a-f0-9]{8}){7}$/);
  assert.equal(p.els.confirmBtn.disabled, true);
  p.els.plain.value = 'must not encrypt';
  await p.click('encryptBtn'); await p.click('decryptBtn'); await p.click('confirmBtn');
  assert.equal(p.els.cipher.value, '');
  assert.equal(p.els.encryptBtn.disabled, true);
  p.els.verifyCheck.checked = true; await p.els.verifyCheck.fire('change');
  assert.equal(p.els.confirmBtn.disabled, false);
  await p.click('confirmBtn'); remote.confirm();
  assert.equal(p.els.encryptBtn.disabled, false);
  await p.click('encryptBtn');
  assert.equal(await remote.decrypt(p.els.cipher.value), 'must not encrypt');
  p.els.cipher.value = await remote.encrypt('received 🔐\n\u0000');
  await p.click('decryptBtn');
  assert.equal(p.els.plain.value, 'received 🔐\n\u0000');
  // An authentication failure must remove previously displayed plaintext.
  p.els.cipher.value = '{}'; await p.click('decryptBtn');
  assert.equal(p.els.plain.value, '');
  await p.click('mismatchBtn'); cleared(p);
  assert.match(p.els.status.textContent, /do not match/i);
  remote.destroy(); await p.dispose();
});

for (const phase of ['generate', 'establish', 'encrypt', 'decrypt']) {
  for (const change of ['reset', 'peer']) {
    for (const failure of [false, true]) {
      test(`${phase}: ${change} invalidates a delayed crypto ${failure ? 'failure' : 'success'} without UI writes`, async () => {
        const p = page(); await p.ready();
        let remote;
        if (phase === 'establish') {
          await p.click('genBtn'); remote = await p.DH.createOffer(); await p.peer(remote.text);
        } else if (phase === 'encrypt' || phase === 'decrypt') {
          remote = await establish(p);
          p.els.plain.value = 'pending secret';
          if (phase === 'decrypt') p.els.cipher.value = await remote.encrypt('pending reply');
        }
        const method = { generate: 'generateKey', establish: 'deriveBits', encrypt: 'encrypt', decrypt: 'decrypt' }[phase];
        const button = { generate: 'genBtn', establish: 'buildSessionBtn', encrypt: 'encryptBtn', decrypt: 'decryptBtn' }[phase];
        const held = p.hold(method, failure), operation = p.click(button);
        await held.started;
        assert.equal(p.els.resetBtn.disabled, false, 'ending must stay available while busy');
        assert.equal(p.els.genBtn.disabled, true);
        assert.equal(p.els.encryptBtn.disabled, true);
        if (change === 'reset') await p.click('resetBtn'); else await p.peer('replacement peer input');
        assert.equal(p.els.plain.value, '');
        assert.equal(p.els.cipher.value, '');
        assert.equal(p.els.fingerprint.value, '');
        assert.equal(p.els.verifyCheck.checked, false);
        // Establish a replacement before the old promise settles: its cleanup must not destroy this session either.
        const replacement = await establish(p);
        p.els.plain.value = 'new session plaintext';
        const expected = p.snapshot();
        held.release(); await operation;
        assert.deepEqual(p.snapshot(), expected, 'stale operation must not change fields, state, styles or buttons');
        await p.click('encryptBtn');
        assert.equal(await replacement.decrypt(p.els.cipher.value), 'new session plaintext');
        replacement.destroy(); remote?.destroy(); await p.dispose();
      });
    }
  }
}

test('pagehide and persisted pageshow clear fields and keys; tab switching preserves a live session', async () => {
  const p = page(); await p.ready();
  let remote = await establish(p);
  p.els.plain.value = 'visible secret';
  const before = p.snapshot();
  p.document.hidden = true; await p.document.fire('visibilitychange');
  p.document.hidden = false; await p.document.fire('visibilitychange');
  await p.window.fire('pageshow', { persisted: false });
  assert.deepEqual(p.snapshot(), before);
  await p.window.fire('pagehide'); cleared(p); remote.destroy();
  await p.click('genBtn'); cleared(p);
  await p.window.fire('pageshow', { persisted: true });
  remote = await establish(p);
  p.els.plain.value = 'restored secret';
  await p.window.fire('pageshow', { persisted: true }); cleared(p);
  assert.match(p.els.status.textContent, /restored page cleared/i);
  remote.destroy(); await p.dispose();
});

test('clipboard denial gives a manual-copy fallback and delayed clipboard results respect the epoch', async () => {
  for (const button of ['copyMyPub', 'copyCipher']) {
    const p = page(); await p.ready();
    const remote = await establish(p);
    if (button === 'copyCipher') { p.els.plain.value = 'copy me'; await p.click('encryptBtn'); }
    p.navigator.clipboard.writeText = async () => { throw new Error('Permission denied'); };
    await p.click(button);
    assert.match(p.els.status.textContent, /select and copy the text manually/i);
    for (const failure of [false, true]) {
      let release;
      p.navigator.clipboard.writeText = () => new Promise((resolve, reject) => {
        release = () => failure ? reject(new Error('Late denial')) : resolve();
      });
      const copying = p.click(button);
      assert.equal(typeof release, 'function');
      await p.click('resetBtn');
      const expected = p.snapshot();
      release(); await copying;
      assert.deepEqual(p.snapshot(), expected);
      if (!failure) {
        const nextRemote = await establish(p);
        nextRemote.destroy();
        if (button === 'copyCipher') { p.els.plain.value = 'copy again'; await p.click('encryptBtn'); }
      }
    }
    remote.destroy(); await p.dispose();
  }
});

for (const failure of [false, true]) {
  test(`startup probe ${failure ? 'failure' : 'success'} after pagehide cannot restore old UI`, async () => {
    const p = page({ manualStart: true });
    const held = p.hold('generateKey', failure);
    p.start(); await held.started;
    await p.window.fire('pagehide');
    const expected = p.snapshot();
    held.release(); await p.idle();
    assert.deepEqual(p.snapshot(), expected, 'capability callbacks must respect the invalidated page generation');
    await p.dispose();
  });
}
