'use strict';

// Run with Node 22+: node --test tests/dh.test.cjs
const test = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');

if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
const source = readFileSync(join(__dirname, '../js/dh.js'), 'utf8');
const { DH } = require('../js/dh.js');
const encoder = new TextEncoder();
const SUITE = 'P256-HKDF-SHA256-A256GCM';
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const mutate = (text, changes) => JSON.stringify({ ...JSON.parse(text), ...changes });
const rejects = operation => assert.rejects(async () => operation());

// Instrument real WebCrypto, never replace cipher results or alter source/constants.
function isolated(hooks = {}) {
  const clock = { wall: 1_800_000_000_000, mono: 1000 };
  const events = [];
  class Clock extends Date {
    constructor(...args) { super(...(args.length ? args : [clock.wall])); }
    static now() { return clock.wall; }
  }
  const subtle = new Proxy(webcrypto.subtle, {
    get(target, method) {
      if (typeof target[method] !== 'function') return target[method];
      return async (...args) => {
        const value = await target[method](...args);
        const event = { method, args, value };
        events.push(event);
        return hooks[method] ? hooks[method](event) : value;
      };
    }
  });
  const context = vm.createContext({
    module: { exports: {} }, TextEncoder, TextDecoder, URL, Date: Clock,
    performance: { now: () => clock.mono },
    crypto: { subtle, getRandomValues: webcrypto.getRandomValues.bind(webcrypto) },
    atob, btoa, setTimeout, clearTimeout, setInterval, clearInterval,
    console, DOMException
  });
  vm.runInContext(source, context, { filename: 'js/dh.js' });
  return { DH: context.module.exports.DH, events, clock };
}

async function pair(core = DH, confirm = true) {
  const [left, right] = await Promise.all([core.createOffer(), core.createOffer()]);
  const [a, b] = await Promise.all([left.establish(right.text), right.establish(left.text)]);
  if (confirm) { a.confirm(); b.confirm(); }
  return { a, b, left, right };
}

function gate() {
  let release, entered;
  const wait = new Promise(resolve => { release = resolve; });
  const started = new Promise(resolve => { entered = resolve; });
  return { release, started, hook: async ({ value }) => { entered(); await wait; return value; } };
}

async function forged(events, model, seq, bytes) {
  const key = events.find(event => event.method === 'encrypt').args[1];
  const payload = { ...JSON.parse(model), seq };
  const iv = new Uint8Array(12);
  new DataView(iv.buffer).setBigUint64(4, BigInt(seq), false);
  const additionalData = encoder.encode(JSON.stringify([2, SUITE, payload.sid, payload.from, seq]));
  payload.ct = b64(await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData, tagLength: 128 }, key, bytes
  ));
  return JSON.stringify(payload);
}

test('v2 offers, constants, directional binding and full safety codes', async () => {
  assert.equal(DH.constants.SUITE, SUITE);
  assert.equal(DH.constants.MAX_OFFER, 4096);
  assert.equal(DH.constants.MAX_PLAIN, 1048576);
  assert.equal(DH.constants.MAX_CIPHER, 1572864);
  assert.equal(DH.constants.MAX_MESSAGES, 65536);
  assert.equal(DH.constants.MAX_BYTES, 67108864);
  assert.equal(DH.constants.TTL, 3600000);
  assert.equal(DH.constants.WINDOW, 128);
  assert.ok(Object.isFrozen(DH.constants));
  const { a, b, left, right } = await pair();
  for (const offer of [left, right]) {
    assert.ok(Object.isFrozen(offer));
    const parsed = JSON.parse(offer.text);
    assert.deepEqual(Object.keys(parsed).sort(), ['nonce', 'pub', 'suite', 'v']);
    assert.equal(parsed.v, 2);
    assert.equal(parsed.suite, SUITE);
    assert.match(parsed.pub, /^[A-Za-z0-9_-]+$/);
    assert.match(parsed.nonce, /^[A-Za-z0-9_-]+$/);
    assert.equal(Buffer.from(parsed.pub, 'base64url').length, 65);
    assert.equal(Buffer.from(parsed.pub, 'base64url')[0], 4);
    assert.equal(Buffer.from(parsed.nonce, 'base64url').length, 32);
    assert.equal(offer.active, false);
  }
  assert.match(a.safetyCode, /^[a-f0-9]{64}$/i);
  assert.equal(a.safetyCode, b.safetyCode);
  assert.equal(a.sid, b.sid);
  const offers = [JSON.parse(left.text), JSON.parse(right.text)].sort((x, y) =>
    Buffer.compare(Buffer.from(x.pub, 'base64url'), Buffer.from(y.pub, 'base64url')));
  const transcript = JSON.stringify(['DH-v2', SUITE, ...offers.map(o => [o.pub, o.nonce])]);
  assert.equal(a.sid, b64(await webcrypto.subtle.digest('SHA-256', encoder.encode(transcript))));
  const first = JSON.parse(await a.encrypt('a'));
  const second = JSON.parse(await b.encrypt('b'));
  assert.equal(first.from, JSON.parse(left.text).pub === offers[0].pub ? 'a' : 'b');
  assert.notEqual(first.from, second.from);
  assert.equal(first.seq, 0);
  assert.equal(second.seq, 0);
  assert.deepEqual(Object.keys(first).sort(), ['ct', 'from', 'seq', 'sid', 'suite', 'v']);
  a.destroy(); b.destroy();
});

test('confirmation is enforced by core; both directions preserve exact text', async () => {
  const { a, b } = await pair(DH, false);
  assert.equal(a.verified, false);
  await rejects(() => a.encrypt('not verified'));
  await rejects(() => a.decrypt('{}'));
  a.confirm();
  const pending = await a.encrypt('verify the receiver separately');
  await rejects(() => b.decrypt(pending));
  b.confirm();
  assert.equal(await b.decrypt(pending), 'verify the receiver separately');
  const texts = ['', '中文与 emoji 🔐👩🏽‍💻', '\uFEFFBOM stays', 'line 1\r\nline 2\n\t\u0000\u0001\u000b\u007f', '  spaces  '];
  for (const text of texts) {
    assert.equal(await b.decrypt(await a.encrypt(text)), text);
    assert.equal(await a.decrypt(await b.encrypt(text)), text);
  }
  await rejects(() => a.encrypt('\ud800'));
  await rejects(() => a.encrypt('\udc00'));
  await rejects(() => a.encrypt({ toString: () => 'implicit coercion' }));
  assert.equal(a.active, true);
  a.destroy(); b.destroy();
  assert.equal(a.active, false);
  assert.equal(a.verified, false);
  assert.throws(() => a.confirm());
  await rejects(() => a.encrypt('ended'));
  await rejects(() => b.decrypt(pending));
});

test('ECDH private and directional AES keys are non-exportable with minimum usages', async () => {
  const inspected = isolated();
  const { a, b } = await pair(inspected.DH);
  const packet = await a.encrypt('inspect parameters');
  await b.decrypt(packet);
  await b.encrypt('reverse');
  const keys = inspected.events.filter(e => ['generateKey', 'deriveKey', 'importKey'].includes(e.method))
    .flatMap(e => e.value?.privateKey ? [e.value.privateKey] : [e.value]);
  const privateKeys = keys.filter(key => key.type === 'private');
  const aesKeys = keys.filter(key => key.algorithm?.name === 'AES-GCM');
  assert.equal(privateKeys.length, 2);
  assert.equal(aesKeys.length, 4);
  for (const key of [...privateKeys, ...aesKeys]) {
    assert.equal(key.extractable, false);
    await assert.rejects(webcrypto.subtle.exportKey(key.type === 'private' ? 'pkcs8' : 'raw', key));
  }
  for (const key of privateKeys) assert.deepEqual(Array.from(key.usages), ['deriveBits']);
  for (const key of aesKeys) {
    assert.equal(key.algorithm.length, 256);
    assert.ok(key.usages.length === 1 && ['encrypt', 'decrypt'].includes(key.usages[0]));
  }
  for (const e of inspected.events.filter(e => ['encrypt', 'decrypt'].includes(e.method))) {
    const p = JSON.parse(packet);
    assert.equal(e.args[0].tagLength, 128);
    assert.equal(Buffer.from(e.args[0].iv).toString('hex'), '000000000000000000000000');
    const metadata = JSON.parse(new TextDecoder().decode(e.args[0].additionalData));
    assert.deepEqual(metadata.slice(0, 3), [2, SUITE, p.sid]);
    assert.equal(metadata[4], 0);
  }
  const labels = inspected.events.filter(e => e.args[0]?.name === 'HKDF')
    .map(e => new TextDecoder().decode(e.args[0].info));
  for (const label of ['DH-v2/a-to-b', 'DH-v2/b-to-a', 'DH-v2/verify']) assert.ok(labels.includes(label));
  for (const e of inspected.events.filter(e => e.args[0]?.name === 'HKDF')) {
    assert.equal(b64(e.args[0].salt), a.sid);
    assert.equal(e.args[0].hash, 'SHA-256');
  }
  a.destroy(); b.destroy();
});

test('offer validation rejects legacy, malformed, noncanonical and invalid-curve inputs', async () => {
  const peer = await DH.createOffer();
  const good = JSON.parse(peer.text);
  const offCurve = new Uint8Array(65); offCurve[0] = 4;
  const variants = [
    '', '{', 'null', '[]', '{}', '"text"', '{"kty":"EC","crv":"P-256"}',
    mutate(peer.text, { v: 1 }), mutate(peer.text, { v: '2' }),
    mutate(peer.text, { suite: 'ECDH-P256/AES-GCM-256' }),
    mutate(peer.text, { extra: true }), mutate(peer.text, { nonce: null }),
    mutate(peer.text, { pub: b64(offCurve) }), mutate(peer.text, { pub: b64(new Uint8Array(33)) }),
    mutate(peer.text, { nonce: good.nonce + '=' }), mutate(peer.text, { pub: good.pub + '\n' }),
    mutate(peer.text, { nonce: b64(new Uint8Array(31)) }), mutate(peer.text, { nonce: '*'.repeat(43) }),
    mutate(peer.text, { nonce: 'A'.repeat(42) + 'B' }),
    peer.text + ' '.repeat(DH.constants.MAX_OFFER)
  ];
  for (const invalid of variants) {
    const mine = await DH.createOffer();
    await rejects(() => mine.establish(invalid));
    await rejects(() => mine.establish(peer.text));
    assert.equal(mine.active, false);
  }
  const own = await DH.createOffer();
  await rejects(() => own.establish(mutate(own.text, { nonce: good.nonce })));
  const reused = await DH.createOffer();
  const session = await reused.establish(peer.text);
  await rejects(() => reused.establish(peer.text));
  session.destroy(); peer.destroy();
});

test('cipher fields, canonical encodings and GCM authentication fail closed', async () => {
  const { a, b } = await pair();
  const packet = await a.encrypt('authenticated');
  const p = JSON.parse(packet);
  const changedTag = Buffer.from(p.ct, 'base64url'); changedTag[changedTag.length - 1] ^= 1;
  const variants = [
    '', '{', 'null', '[]', '{}', '"text"', '{"v":1,"alg":"old","iv":"AA","ct":"AA"}',
    mutate(packet, { v: 1 }), mutate(packet, { suite: 'other' }),
    mutate(packet, { sid: b64(new Uint8Array(32)) }),
    mutate(packet, { from: p.from === 'a' ? 'b' : 'a' }), mutate(packet, { from: 'c' }),
    mutate(packet, { seq: p.seq + 100 }), mutate(packet, { seq: -1 }),
    mutate(packet, { seq: 1.5 }), mutate(packet, { seq: '0' }), mutate(packet, { seq: Number.MAX_SAFE_INTEGER + 1 }),
    mutate(packet, { seq: DH.constants.MAX_MESSAGES }),
    mutate(packet, { ct: b64(changedTag) }), mutate(packet, { ct: p.ct + '=' }),
    mutate(packet, { ct: b64(new Uint8Array(15)) }), mutate(packet, { ct: null }),
    mutate(packet, { iv: b64(new Uint8Array(12)) }), mutate(packet, { extra: 1 }),
    packet + ' '.repeat(DH.constants.MAX_CIPHER)
  ];
  for (const invalid of variants) await rejects(() => b.decrypt(invalid));
  assert.equal(b.active, true);
  assert.equal(await b.decrypt(packet), 'authenticated');
  await rejects(() => a.decrypt(packet));
  const other = await pair();
  await rejects(() => other.b.decrypt(packet));
  a.destroy(); b.destroy(); other.a.destroy(); other.b.destroy();
});

test('128-message receive window allows out-of-order messages and rejects replays at its boundary', async () => {
  const { a, b } = await pair();
  const packets = [];
  for (let i = 0; i < 130; i++) packets.push(await a.encrypt(String(i)));
  assert.equal(await b.decrypt(packets[129]), '129');
  assert.equal(await b.decrypt(packets[2]), '2');
  await rejects(() => b.decrypt(packets[1]));
  await rejects(() => b.decrypt(packets[0]));
  assert.equal(await b.decrypt(packets[128]), '128');
  await rejects(() => b.decrypt(packets[129]));
  await rejects(() => b.decrypt(packets[2]));
  a.destroy(); b.destroy();
});

test('bad authentication cannot advance the receive window; concurrent replays succeed once', async () => {
  const { a, b } = await pair();
  const zero = await a.encrypt('zero');
  let high;
  for (let i = 1; i <= 130; i++) high = await a.encrypt(String(i));
  const bytes = Buffer.from(JSON.parse(high).ct, 'base64url'); bytes[0] ^= 1;
  await rejects(() => b.decrypt(mutate(high, { ct: b64(bytes) })));
  assert.equal(await b.decrypt(zero), 'zero');
  const results = await Promise.allSettled([b.decrypt(high), b.decrypt(high)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.filter(result => result.status === 'rejected').length, 1);
  await rejects(() => b.decrypt(high));
  a.destroy(); b.destroy();
});

test('failed send burns its nonce and concurrent sends reserve distinct sequence numbers', async () => {
  let fail = true;
  const inspected = isolated({ encrypt: ({ value }) => {
    if (fail) { fail = false; throw new Error('injected lost encryption result'); }
    return value;
  } });
  const { a, b } = await pair(inspected.DH);
  await rejects(() => a.encrypt('lost'));
  const packets = await Promise.all(Array.from({ length: 12 }, (_, i) => a.encrypt(String(i))));
  assert.deepEqual(packets.map(p => JSON.parse(p).seq).sort((x, y) => x - y), Array.from({ length: 12 }, (_, i) => i + 1));
  for (let i = 0; i < packets.length; i++) assert.equal(await b.decrypt(packets[i]), String(i));
  const ivs = inspected.events.filter(e => e.method === 'encrypt').map(e => Buffer.from(e.args[0].iv).toString('hex'));
  assert.equal(new Set(ivs).size, 13);
  assert.equal(ivs[0], '000000000000000000000000');
  assert.equal(ivs[1], '000000000000000000000001');
  a.destroy(); b.destroy();
});

test('destroying a pending handshake or cipher operation invalidates its eventual result', async () => {
  for (const method of ['deriveBits', 'encrypt', 'decrypt']) {
    const held = gate();
    let armed = method === 'deriveBits';
    const inspected = isolated({ [method]: event => armed ? held.hook(event) : event.value });
    if (method === 'deriveBits') {
      const mine = await inspected.DH.createOffer();
      const peer = await inspected.DH.createOffer();
      const operation = mine.establish(peer.text);
      const result = rejects(() => operation);
      await held.started;
      mine.destroy(); held.release();
      await result;
      assert.equal(mine.active, false);
      peer.destroy();
    } else {
      const { a, b } = await pair(inspected.DH);
      const packet = method === 'decrypt' ? await a.encrypt('pending') : null;
      armed = true;
      const target = method === 'encrypt' ? a : b;
      const operation = method === 'encrypt' ? target.encrypt('pending') : target.decrypt(packet);
      const result = rejects(() => operation);
      await held.started;
      target.destroy(); held.release();
      await result;
      assert.equal(target.active, false);
      a.destroy(); b.destroy();
    }
  }
});

test('UTF-8 and JSON size limits reject excess without truncation or disabling a valid session', async () => {
  const { a, b } = await pair();
  const maximum = 'a'.repeat(DH.constants.MAX_PLAIN);
  assert.equal(await b.decrypt(await a.encrypt(maximum)), maximum);
  await rejects(() => a.encrypt(maximum + 'a'));
  await rejects(() => a.encrypt('界'.repeat(Math.floor(DH.constants.MAX_PLAIN / 3) + 1)));
  await rejects(() => b.decrypt(' '.repeat(DH.constants.MAX_CIPHER + 1)));
  assert.equal(a.active, true);
  assert.equal(b.active, true);
  assert.equal(await b.decrypt(await a.encrypt('after rejection')), 'after rejection');
  a.destroy(); b.destroy();
});

test('deadlines are rechecked after awaited generation, derivation and cipher operations', async () => {
  for (const method of ['generateKey', 'deriveBits', 'encrypt', 'decrypt']) {
    const held = gate();
    let armed = method === 'generateKey';
    const inspected = isolated({ [method]: event => armed ? held.hook(event) : event.value });
    let operation, target, peer;
    if (method === 'generateKey') {
      operation = inspected.DH.createOffer();
    } else if (method === 'deriveBits') {
      target = await inspected.DH.createOffer();
      peer = await inspected.DH.createOffer();
      armed = true;
      operation = target.establish(peer.text);
    } else {
      const { a, b } = await pair(inspected.DH);
      target = method === 'encrypt' ? a : b;
      peer = method === 'encrypt' ? b : a;
      const packet = method === 'decrypt' ? await a.encrypt('in flight') : null;
      armed = true;
      operation = method === 'encrypt' ? a.encrypt('in flight') : b.decrypt(packet);
    }
    const result = rejects(() => operation);
    await held.started;
    inspected.clock.wall += DH.constants.TTL;
    held.release();
    await result;
    if (target) { assert.equal(target.active, false); target.destroy(); }
    if (peer) peer.destroy();
  }
});

test('authenticated invalid UTF-8 is rejected, and receive byte quota is enforced independently', async () => {
  const inspected = isolated();
  const { a, b } = await pair(inspected.DH);
  const model = await a.encrypt('model');
  await rejects(async () => b.decrypt(await forged(inspected.events, model, 0, new Uint8Array([0xff]))));
  assert.equal(await b.decrypt(model), 'model');
  const block = new Uint8Array(DH.constants.MAX_PLAIN);
  for (let i = 1; i < 64; i++) {
    const p = await forged(inspected.events, model, i, block);
    assert.equal((await b.decrypt(p)).length, block.length);
  }
  const remainder = new Uint8Array(DH.constants.MAX_PLAIN - 5);
  assert.equal((await b.decrypt(await forged(inspected.events, model, 64, remainder))).length, remainder.length);
  await rejects(async () => b.decrypt(await forged(inspected.events, model, 65, new Uint8Array([1]))));
  assert.equal(b.active, false);
  a.destroy();
});

test('64 MiB sending quota ends the session before an over-budget send', async () => {
  const { a, b } = await pair();
  const block = 'x'.repeat(DH.constants.MAX_PLAIN);
  for (let i = 0; i < 64; i++) await a.encrypt(block);
  await rejects(() => a.encrypt('x'));
  assert.equal(a.active, false);
  b.destroy();
});

test('65,536-message sending quota includes empty messages and never wraps sequence numbers', async () => {
  const { a, b } = await pair();
  for (let i = 0; i < DH.constants.MAX_MESSAGES; i++) {
    const p = JSON.parse(await a.encrypt(''));
    assert.equal(p.seq, i);
  }
  await rejects(() => a.encrypt(''));
  assert.equal(a.active, false);
  b.destroy();
});

test('offer lifetime carries into the session and monotonic time prevents wall-clock rollback', async () => {
  const inspected = isolated();
  const mine = await inspected.DH.createOffer();
  assert.equal(mine.expiresAt, inspected.clock.wall + DH.constants.TTL);
  const peer = await inspected.DH.createOffer();
  inspected.clock.wall += DH.constants.TTL - 1;
  inspected.clock.mono += DH.constants.TTL - 1;
  const session = await mine.establish(peer.text);
  assert.equal(session.expiresAt, mine.expiresAt);
  session.confirm();
  inspected.clock.wall += 1;
  await rejects(() => session.encrypt('expired'));
  assert.equal(session.active, false);
  peer.destroy();
  const next = await pair(inspected.DH);
  inspected.clock.wall -= DH.constants.TTL;
  inspected.clock.mono += DH.constants.TTL;
  await rejects(() => next.a.encrypt('clock rolled back'));
  assert.equal(next.a.active, false);
  next.b.destroy();
  const expired = await inspected.DH.createOffer();
  const remote = await inspected.DH.createOffer();
  inspected.clock.wall += DH.constants.TTL;
  await rejects(() => expired.establish(remote.text));
  assert.equal(expired.active, false);
  remote.destroy();
});

test('origin checks require HTTPS or secure loopback HTTP, never file or lookalike hosts', () => {
  for (const url of ['https://secure.example/DH.html', 'http://localhost:8000/DH.html', 'http://127.0.0.1/DH.html', 'http://[::1]/DH.html']) {
    assert.equal(DH.supportedOrigin(new URL(url), true), true, url);
    assert.equal(DH.supportedOrigin(new URL(url), false), false, url);
  }
  for (const url of ['file:///tmp/DH.html', 'http://example.com/DH.html', 'http://localhost.evil.test/DH.html', 'http://192.168.1.1/DH.html', 'data:text/html,test']) {
    assert.equal(DH.supportedOrigin(new URL(url), true), false, url);
  }
});
