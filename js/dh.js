'use strict';

// DH v2: see DH-SECURITY.md for the wire format, trust assumptions and limits.
const DH = (() => {
  const constants = Object.freeze({
    SUITE: 'P256-HKDF-SHA256-A256GCM', MAX_OFFER: 4096,
    MAX_PLAIN: 1024 * 1024, MAX_CIPHER: 1.5 * 1024 * 1024,
    MAX_MESSAGES: 65536, MAX_BYTES: 64 * 1024 * 1024, TTL: 3600000, WINDOW: 128
  });
  const { SUITE, MAX_OFFER, MAX_PLAIN, MAX_CIPHER, MAX_MESSAGES, MAX_BYTES, TTL, WINDOW } = constants;
  const ec = { name: 'ECDH', namedCurve: 'P-256' };
  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  const encode = value => encoder.encode(JSON.stringify(value));
  const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  const mask = (1n << BigInt(WINDOW)) - 1n;

  function base64url(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i += 8192) {
      binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function decode64(value, min, max = min) {
    if (typeof value !== 'string' || value.length > Math.ceil(max * 4 / 3) ||
        !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid Base64url encoding.');
    let bytes;
    try {
      bytes = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    } catch { throw new Error('Invalid Base64url encoding.'); }
    if (bytes.length < min || bytes.length > max || base64url(bytes) !== value) {
      throw new Error('Invalid encoded length or noncanonical Base64url.');
    }
    return bytes;
  }

  function parse(text, max, fields) {
    if (typeof text !== 'string' || text.length > max || encoder.encode(text).length > max) {
      throw new Error('Input exceeds the size limit.');
    }
    let value;
    try { value = JSON.parse(text); } catch { throw new Error('Input is not valid JSON.'); }
    if (!value || Array.isArray(value) || typeof value !== 'object' ||
        Object.keys(value).length !== fields.length || fields.some(key => !Object.hasOwn(value, key))) {
      throw new Error('Unexpected protocol fields.');
    }
    if (value.v !== 2 || value.suite !== SUITE) throw new Error('Only the DH v2 suite is supported.');
    return value;
  }

  function supportedOrigin(location, secure) {
    return secure === true && (location.protocol === 'https:' ||
      (location.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname)));
  }

  async function createOffer() {
    const started = Date.now(), monotonic = performance.now();
    const expiresAt = started + TTL;
    const expired = () => Date.now() >= expiresAt || performance.now() - monotonic >= TTL;
    let pair = await crypto.subtle.generateKey(ec, false, ['deriveBits']);
    let privateKey = pair.privateKey;
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    pair = null;
    const offer = { v: 2, suite: SUITE, pub: base64url(pub), nonce: base64url(crypto.getRandomValues(new Uint8Array(32))) };
    let consumed = false, destroyed = false;
    const destroy = () => { destroyed = true; privateKey = null; };
    const assertAlive = () => {
      if (destroyed || expired()) { destroy(); throw new Error('Handshake ended or expired. Generate a new one.'); }
    };
    assertAlive();

    return Object.freeze({
      text: JSON.stringify(offer, null, 2), expiresAt,
      get active() { if (expired()) destroy(); return !destroyed && !consumed; },
      destroy,
      async establish(peerText) {
        assertAlive();
        if (consumed) throw new Error('This handshake has already been used. Generate a new one.');
        // Consume before any await, including failed attempts; never reset a nonce under the same key.
        consumed = true;
        let secret = null, material = null, verification = null, ownPrivate = privateKey;
        privateKey = null;
        try {
          const peer = parse(peerText, MAX_OFFER, ['v', 'suite', 'pub', 'nonce']);
          const peerBytes = decode64(peer.pub, 65);
          decode64(peer.nonce, 32);
          if (peerBytes[0] !== 4 || peer.pub === offer.pub) throw new Error('Invalid or identical peer public key.');
          const peerKey = await crypto.subtle.importKey('raw', peerBytes, ec, false, []);
          assertAlive();
          // Byte ordering, never locale-dependent string ordering.
          const different = pub.findIndex((b, i) => b !== peerBytes[i]);
          const from = pub[different] < peerBytes[different] ? 'a' : 'b';
          const [a, b] = from === 'a' ? [offer, peer] : [peer, offer];
          const transcript = encode(['DH-v2', SUITE, [a.pub, a.nonce], [b.pub, b.nonce]]);
          const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', transcript));
          assertAlive();
          secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, ownPrivate, 256));
          ownPrivate = null;
          assertAlive();
          material = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey', 'deriveBits']);
          secret.fill(0);
          assertAlive();
          const params = label => ({ name: 'HKDF', hash: 'SHA-256', salt: hash, info: encoder.encode('DH-v2/' + label) });
          const key = (label, usage) => crypto.subtle.deriveKey(params(label), material,
            { name: 'AES-GCM', length: 256 }, false, [usage]);
          const tx = await key(from === 'a' ? 'a-to-b' : 'b-to-a', 'encrypt');
          assertAlive();
          const rx = await key(from === 'a' ? 'b-to-a' : 'a-to-b', 'decrypt');
          assertAlive();
          verification = new Uint8Array(await crypto.subtle.deriveBits(params('verify'), material, 256));
          assertAlive();
          return createSession(tx, rx, from, base64url(hash), hex(verification), expiresAt, expired);
        } finally {
          ownPrivate = null;
          material = null;
          if (secret) secret.fill(0);
          if (verification) verification.fill(0);
        }
      }
    });
  }

  function createSession(tx, rx, from, sid, safetyCode, expiresAt, expired) {
    let verified = false, nextSeq = 0, txBytes = 0, rxBytes = 0, rxCount = 0;
    let highest = -1, received = 0n;
    const peer = from === 'a' ? 'b' : 'a';
    const destroy = () => { tx = null; rx = null; verified = false; received = 0n; };
    const active = () => { if (expired()) destroy(); return tx !== null && rx !== null; };
    const requireActive = () => { if (!active()) throw new Error('Session ended or expired. Start a new handshake.'); };
    const requireVerified = () => {
      requireActive();
      if (!verified) throw new Error('Verify the entire safety code through an independent trusted channel first.');
    };
    const quota = (count, bytes) => {
      if (count >= MAX_MESSAGES || bytes > MAX_BYTES) {
        destroy(); throw new Error('Session limit reached. Start a new handshake.');
      }
    };
    const fresh = seq => {
      const offset = highest - seq;
      if (offset >= WINDOW || (offset >= 0 && (received & (1n << BigInt(offset))) !== 0n)) {
        throw new Error('Duplicate or too-old message.');
      }
    };
    const accept = seq => {
      if (seq > highest) {
        const advance = seq - highest;
        received = advance >= WINDOW ? 1n : ((received << BigInt(advance)) | 1n) & mask;
        highest = seq;
      } else { received |= 1n << BigInt(highest - seq); }
    };
    const algorithm = (sender, seq) => {
      const iv = new Uint8Array(12);
      new DataView(iv.buffer).setBigUint64(4, BigInt(seq), false);
      return { name: 'AES-GCM', iv, tagLength: 128, additionalData: encode([2, SUITE, sid, sender, seq]) };
    };

    return Object.freeze({
      sid, safetyCode, expiresAt,
      get active() { return active(); },
      get verified() { return active() && verified; },
      confirm() { requireActive(); verified = true; },
      destroy,
      async encrypt(plaintext) {
        requireVerified();
        if (typeof plaintext !== 'string' || plaintext.length > MAX_PLAIN) throw new Error('Plaintext exceeds 1 MiB.');
        const data = encoder.encode(plaintext);
        try {
          if (data.length > MAX_PLAIN) throw new Error('Plaintext exceeds 1 MiB in UTF-8.');
          if (decoder.decode(data) !== plaintext) throw new Error('Plaintext contains an unpaired Unicode surrogate.');
          quota(nextSeq, txBytes + data.length);
          // Reserve synchronously. Failed operations consume both sequence and byte budget.
          const seq = nextSeq++;
          txBytes += data.length;
          const encrypted = await crypto.subtle.encrypt(algorithm(from, seq), tx, data);
          requireVerified();
          return JSON.stringify({ v: 2, suite: SUITE, sid, from, seq, ct: base64url(new Uint8Array(encrypted)) });
        } finally { data.fill(0); }
      },
      async decrypt(ciphertext) {
        requireVerified();
        const value = parse(ciphertext, MAX_CIPHER, ['v', 'suite', 'sid', 'from', 'seq', 'ct']);
        if (value.sid !== sid || value.from !== peer) throw new Error('Wrong session or message direction.');
        if (!Number.isSafeInteger(value.seq) || Object.is(value.seq, -0) || value.seq < 0 || value.seq >= MAX_MESSAGES) {
          throw new Error('Invalid message sequence.');
        }
        const ct = decode64(value.ct, 16, MAX_PLAIN + 16);
        fresh(value.seq);
        let plaintext;
        try {
          plaintext = new Uint8Array(await crypto.subtle.decrypt(algorithm(value.from, value.seq), rx, ct));
        } catch { throw new Error('Message authentication failed.'); }
        try {
          requireVerified();
          // Authentication can complete out of order: recheck and commit without an await.
          fresh(value.seq);
          quota(rxCount, rxBytes + plaintext.length);
          const text = decoder.decode(plaintext);
          accept(value.seq);
          rxCount++;
          rxBytes += plaintext.length;
          return text;
        } finally { plaintext.fill(0); }
      }
    });
  }

  async function checkCapabilities() {
    let a, b, sa, sb;
    try {
      a = await createOffer(); b = await createOffer();
      sa = await a.establish(b.text); sb = await b.establish(a.text);
      if (sa.safetyCode !== sb.safetyCode) throw new Error('Crypto self-check failed.');
      sa.confirm(); sb.confirm();
      if (await sb.decrypt(await sa.encrypt('')) !== '') throw new Error('Crypto self-check failed.');
    } finally {
      a?.destroy(); b?.destroy(); sa?.destroy(); sb?.destroy();
    }
  }

  return Object.freeze({ constants, createOffer, supportedOrigin, checkCapabilities });
})();

function setupPage() {
  const els = Object.fromEntries(Array.from(document.querySelectorAll('[data-id]'), e => [e.dataset.id, e]));
  let local = null, session = null, epoch = 0, busy = false, ready = false, timer = null;
  let capabilityCheck = null, suspended = false;
  let stage = 'Not started';
  const setStatus = (message, kind = '') => {
    els.status.textContent = message;
    els.status.className = 'footer ' + kind;
  };
  function render() {
    const verified = !!session?.verified;
    const usable = ready && !suspended;
    els.sessionState.textContent = stage;
    els.genBtn.disabled = !usable || busy;
    els.copyMyPub.disabled = !usable || !els.myPub.value;
    els.peerPub.disabled = !usable || !els.myPub.value;
    els.buildSessionBtn.disabled = !usable || busy || !local?.active;
    els.verifyCheck.disabled = !usable || busy || !session?.active || verified;
    els.confirmBtn.disabled = els.verifyCheck.disabled || !els.verifyCheck.checked;
    els.mismatchBtn.disabled = !session?.active;
    els.plain.disabled = els.cipher.disabled = !verified || busy;
    els.encryptBtn.disabled = els.decryptBtn.disabled = !verified || busy;
    els.copyCipher.disabled = !verified || busy || !els.cipher.value;
    const expires = session?.expiresAt || local?.expiresAt;
    els.expiresAt.textContent = expires ? new Date(expires).toLocaleTimeString() : '—';
  }
  function observeCapabilities() {
    const operation = epoch;
    capabilityCheck.then(() => {
      if (operation !== epoch || suspended) return;
      ready = true; render();
    }).catch(() => {
      if (operation !== epoch || suspended) return;
      document.getElementById('compat-warning').hidden = false;
      setStatus('Required cryptographic capabilities are unavailable. No insecure fallback is provided.', 'err');
    });
  }
  function clearMessages() {
    els.plain.value = els.cipher.value = els.fingerprint.value = '';
    els.verifyCheck.checked = false;
  }
  function reset(message = 'Session ended and cleared. Generate a fresh handshake to continue.') {
    ++epoch;
    local?.destroy(); session?.destroy();
    local = session = null;
    clearTimeout(timer); timer = null;
    busy = false;
    clearMessages();
    els.myPub.value = els.peerPub.value = '';
    stage = 'Ended';
    setStatus(message);
    render();
    // A new page generation may observe the same capability result, never an old callback.
    if (capabilityCheck && !ready && !suspended) observeCapabilities();
  }
  function expireIfNeeded() {
    if ((session && !session.active) || (local && !busy && !local.active)) {
      reset('Session ended or expired. Generate a fresh handshake.');
      return true;
    }
    return false;
  }

  els.resetBtn.addEventListener('click', () => reset());
  els.mismatchBtn.addEventListener('click', () => reset('Safety codes do not match. Session ended; do not exchange sensitive messages.'));
  els.genBtn.addEventListener('click', async () => {
    if (!ready || suspended || busy) return;
    reset('Generating a fresh handshake...');
    const operation = epoch;
    busy = true; stage = 'Generating'; render();
    try {
      const result = await DH.createOffer();
      if (operation !== epoch) { result.destroy(); return; }
      local = result;
      els.myPub.value = local.text;
      stage = 'Waiting for peer';
      setStatus('Send your handshake to your peer, then paste theirs. Private keys stay in this page.');
      timer = setTimeout(() => {
        if (operation === epoch) reset('One-hour lifetime reached. Generate a fresh handshake.');
      }, Math.max(0, local.expiresAt - Date.now()));
    } catch {
      if (operation === epoch) { stage = 'Ended'; setStatus('Could not generate a handshake.', 'err'); }
    } finally {
      if (operation === epoch) { busy = false; render(); }
    }
  });

  els.peerPub.addEventListener('input', () => {
    if (suspended) return;
    ++epoch;
    session?.destroy(); session = null;
    // An unconsumed offer can still be used. A consumed/pending one must be replaced.
    if (local && !local.active) { local.destroy(); local = null; }
    busy = false;
    clearMessages();
    clearTimeout(timer); timer = null;
    if (local) {
      const operation = epoch;
      timer = setTimeout(() => {
        if (operation === epoch) reset('One-hour lifetime reached. Generate a fresh handshake.');
      }, Math.max(0, local.expiresAt - Date.now()));
    } else { els.myPub.value = ''; }
    stage = local ? 'Waiting for peer' : 'Ended';
    setStatus(local ? 'Peer handshake changed. Establish and verify a session before messaging.' :
      'Previous session ended. Generate and exchange fresh handshakes.');
    render();
  });

  els.buildSessionBtn.addEventListener('click', async () => {
    if (!ready || suspended || busy || !local?.active) return;
    const operation = epoch;
    busy = true; stage = 'Establishing'; clearMessages(); render();
    try {
      const result = await local.establish(els.peerPub.value);
      if (operation !== epoch) { result.destroy(); return; }
      local = null; session = result;
      els.fingerprint.value = session.safetyCode.match(/.{8}/g).join(' ');
      stage = 'Awaiting verification';
      setStatus('Compare ALL safety-code characters through an independent trusted channel. Messaging is locked.', 'warn');
    } catch {
      if (operation === epoch) reset('Handshake failed or expired. Generate and exchange fresh v2 handshakes.');
    } finally {
      if (operation === epoch) { busy = false; render(); }
    }
  });

  els.verifyCheck.addEventListener('change', render);
  els.confirmBtn.addEventListener('click', () => {
    if (busy || !els.verifyCheck.checked || !session || expireIfNeeded()) return;
    session.confirm();
    stage = 'Verified';
    setStatus('Safety code confirmed locally. Your peer must independently verify it too.', 'ok');
    render();
  });

  async function messageOperation(encrypting) {
    if (busy || expireIfNeeded() || !session?.verified) return;
    const operation = epoch, current = session;
    const input = encrypting ? els.plain.value : els.cipher.value;
    if (encrypting) els.cipher.value = ''; else els.plain.value = '';
    busy = true; render();
    setStatus(encrypting ? 'Encrypting...' : 'Authenticating and decrypting...');
    try {
      const result = await (encrypting ? current.encrypt(input) : current.decrypt(input));
      if (operation !== epoch) return;
      (encrypting ? els.cipher : els.plain).value = result;
      setStatus(encrypting ? 'Encrypted. Send the ciphertext to your peer.' : 'Authenticated message decrypted.', 'ok');
    } catch (error) {
      if (operation === epoch) setStatus(error.message, 'err');
    } finally {
      if (operation === epoch) { busy = false; if (!expireIfNeeded()) render(); }
    }
  }
  els.encryptBtn.addEventListener('click', () => messageOperation(true));
  els.decryptBtn.addEventListener('click', () => messageOperation(false));
  els.cipher.addEventListener('input', render);
  for (const [button, field] of [[els.copyMyPub, els.myPub], [els.copyCipher, els.cipher]]) {
    button.addEventListener('click', async () => {
      if (button.disabled || expireIfNeeded()) return;
      const operation = epoch;
      try {
        await navigator.clipboard.writeText(field.value);
        if (operation === epoch) setStatus('Copied.', 'ok');
      } catch {
        if (operation === epoch) setStatus('Clipboard unavailable. Select and copy the text manually.', 'warn');
      }
    });
  }

  window.addEventListener('pagehide', () => { suspended = true; reset(); });
  window.addEventListener('pageshow', event => {
    if (event.persisted) { suspended = false; reset('Restored page cleared. Start a fresh handshake.'); }
  });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) expireIfNeeded(); });
  reset('Generate a fresh handshake to begin.');
  stage = 'Not started'; render();
  if (!DH.supportedOrigin(window.location, window.isSecureContext) ||
      !globalThis.crypto?.subtle || window.top !== window.self) {
    document.getElementById('compat-warning').hidden = false;
    setStatus('Unavailable: use a supported browser over HTTPS or loopback HTTP, in a top-level page.', 'err');
    return;
  }
  // Keep every cryptographic control disabled until all required algorithms actually work.
  capabilityCheck = DH.checkCapabilities();
  observeCapabilities();
}

if (typeof module !== 'undefined' && module.exports) module.exports = { DH, setupPage };
if (typeof window !== 'undefined') window.addEventListener('DOMContentLoaded', setupPage);
