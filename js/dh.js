// ECDH (P-256) + AES-GCM demo helpers
// Demo only. Do not use as-is for production.

const DH = (() => {
  const curve = 'P-256';
  const algoECDH = { name: 'ECDH', namedCurve: curve };

  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  // Utils
  const bufToB64 = (buf) => {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  };

  const b64ToBuf = (b64) => {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  };

  const hex = (buf) => Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
  const sha256 = async (buf) => crypto.subtle.digest('SHA-256', buf);

  // Keys
  async function generateKeyPair() {
    return crypto.subtle.generateKey(algoECDH, true, ['deriveKey','deriveBits']);
  }

  async function exportPublicJwk(publicKey) {
    const jwk = await crypto.subtle.exportKey('jwk', publicKey);
    return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, ext: true };
  }

  async function exportPrivateJwk(privateKey, publicKey) {
    const priv = await crypto.subtle.exportKey('jwk', privateKey);
    let pub;
    try { pub = await crypto.subtle.exportKey('jwk', publicKey); } catch { pub = {}; }
    return {
      kty: priv.kty,
      crv: priv.crv || 'P-256',
      d: priv.d,
      x: priv.x || pub.x,
      y: priv.y || pub.y,
      ext: true,
      key_ops: ['deriveKey','deriveBits']
    };
  }

  async function importPeerPublicJwk(jwk) {
    if (!jwk || jwk.kty !== 'EC') throw new Error('Invalid JWK public key');
    return crypto.subtle.importKey('jwk', jwk, algoECDH, true, []);
  }

  async function importPrivateJwk(jwk) {
    if (!jwk || jwk.kty !== 'EC' || !jwk.d) throw new Error('Invalid JWK private key (must include d)');
    const priv = await crypto.subtle.importKey('jwk', { ...jwk, key_ops:['deriveKey','deriveBits'] }, algoECDH, true, ['deriveKey','deriveBits']);
    let pub = null;
    if (jwk.x && jwk.y) {
      pub = await crypto.subtle.importKey('jwk', { kty:'EC', crv: jwk.crv || 'P-256', x: jwk.x, y: jwk.y, ext:true }, algoECDH, true, []);
    }
    return { privateKey: priv, publicKey: pub };
  }

  async function deriveAesKey(myPrivateKey, peerPublicKey) {
    return crypto.subtle.deriveKey({ name:'ECDH', public: peerPublicKey }, myPrivateKey, { name:'AES-GCM', length:256 }, true, ['encrypt','decrypt']);
  }

  // Crypto
  async function encrypt(aesKey, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = textEncoder.encode(plaintext);
    const ctBuf = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aesKey, data);
    return { v:1, alg:'ECDH-P256/AES-GCM-256', iv: bufToB64(iv), ct: bufToB64(ctBuf) };
  }

  async function decrypt(aesKey, payload) {
    if (!payload || typeof payload !== 'object') throw new Error('Invalid ciphertext format');
    const iv = new Uint8Array(b64ToBuf(payload.iv));
    const ctBuf = b64ToBuf(payload.ct);
    const ptBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, aesKey, ctBuf);
    return textDecoder.decode(ptBuf);
  }

  async function keyFingerprint(aesKey) {
    const raw = await crypto.subtle.exportKey('raw', aesKey);
    const h = await sha256(raw);
    return hex(h);
  }

  return { generateKeyPair, exportPublicJwk, exportPrivateJwk, importPeerPublicJwk, importPrivateJwk, deriveAesKey, encrypt, decrypt, keyFingerprint };
})();

// Single-page wiring (DH.html)
function setupPage() {
  const els = Object.fromEntries(Array.from(document.querySelectorAll('[data-id]')).map(e=>[e.dataset.id,e]));

  let myKeys = /** @type {CryptoKeyPair|null} */(null);
  let sessionKey = /** @type {CryptoKey|null} */(null);

  function setStatus(msg, cls=''){
    els.status.textContent = msg;
    els.status.className = `muted ${cls}`.trim();
  }

  function setImportStatus(msg, cls=''){
    if (!els.importStatus) return;
    els.importStatus.textContent = msg;
    els.importStatus.className = `footer muted ${cls}`.trim();
  }

  function enableSession(enabled){
    els.encryptBtn.disabled = !enabled;
    els.decryptBtn.disabled = !enabled;
  }

  function enableAfterKeys(enabled){
    els.copyMyPub.disabled = !enabled;
    els.peerPub.disabled = !enabled;
    els.buildSessionBtn.disabled = !enabled;
  }

  // Input sanitization (strip most control chars, but KEEP tabs/newlines)
  // Removes: U+0000–0008, 000B–000C, 000E–001F, 007F
  // Keeps: \t (U+0009), \n (U+000A), \r (U+000D)
  const sanitize = (s) => (s ?? '').toString().replace(/[\u0000-\u0008\u000B-\u000C\u000E-\u001F\u007F]/g, '');
  document.querySelectorAll('[data-sanitize]').forEach((el) => {
    el.addEventListener('input', () => { el.value = sanitize(el.value); });
    el.addEventListener('paste', () => { setTimeout(()=>{ el.value = sanitize(el.value); }, 0); });
  });

  // Generate key pair
  els.genBtn.addEventListener('click', async ()=>{
    try{
      setStatus('Generating key pair...');
      myKeys = await DH.generateKeyPair();
      const pubJwk = await DH.exportPublicJwk(myKeys.publicKey);
      const privJwk = await DH.exportPrivateJwk(myKeys.privateKey, myKeys.publicKey);
      els.myPub.value = JSON.stringify(pubJwk, null, 2);
      if (els.privJwk) els.privJwk.value = JSON.stringify(privJwk, null, 2);
      enableAfterKeys(true);
      setStatus('Key pair generated. Share your public key; keep private key secret.', 'ok');
    }catch(err){
      console.error(err);
      setStatus('Generation failed: ' + err.message, 'err');
    }
  });

  // Copy public key
  els.copyMyPub.addEventListener('click', async ()=>{
    try{
      await navigator.clipboard.writeText(els.myPub.value.trim());
      setStatus('Public key copied.', 'ok');
    }catch{
      setStatus('Copy failed, please copy manually.', 'warn');
    }
  });

  // Import private key
  if (els.importPrivBtn) {
    els.importPrivBtn.addEventListener('click', async ()=>{
      try{
        const src = (els.privJwk ? els.privJwk.value : '').trim();
        if (!src) throw new Error('Paste a private key JWK');
        let jwk;
        try { jwk = JSON.parse(src); } catch { throw new Error('Private key is not valid JSON'); }
        const pair = await DH.importPrivateJwk(jwk);
        if (!pair.publicKey) throw new Error('Private JWK missing x/y; include public coordinates');
        myKeys = { privateKey: pair.privateKey, publicKey: pair.publicKey };
        const pubJwk = await DH.exportPublicJwk(myKeys.publicKey);
        const privJwk = await DH.exportPrivateJwk(myKeys.privateKey, myKeys.publicKey);
        els.myPub.value = JSON.stringify(pubJwk, null, 2);
        if (els.privJwk) els.privJwk.value = JSON.stringify(privJwk, null, 2);
        enableAfterKeys(true);
        setStatus('Private key imported. Public key restored from JWK.', 'ok');
        setImportStatus('Private key imported successfully.', 'ok');
      }catch(err){
        console.error(err);
        setStatus('Import failed: ' + err.message, 'err');
        setImportStatus('Import failed: ' + err.message, 'err');
      }
    });
  }

  // Establish session
  els.buildSessionBtn.addEventListener('click', async ()=>{
    try{
      if (!myKeys) throw new Error('Generate or import your key pair first');
      const peerStr = els.peerPub.value.trim();
      if (!peerStr) throw new Error('Paste peer public key (JWK JSON)');
      let jwk;
      try { jwk = JSON.parse(peerStr); } catch { throw new Error('Peer public key is not valid JSON'); }
      const peerPub = await DH.importPeerPublicJwk(jwk);
      sessionKey = await DH.deriveAesKey(myKeys.privateKey, peerPub);
      els.fingerprint.value = await DH.keyFingerprint(sessionKey);
      enableSession(true);
      setStatus('Session key established. Verify fingerprints match on both sides.', 'ok');
    }catch(err){
      console.error(err);
      setStatus('Establish failed: ' + err.message, 'err');
    }
  });

  // Encrypt
  els.encryptBtn.addEventListener('click', async ()=>{
    try{
      if (!sessionKey) throw new Error('Session key is not established');
      const payload = await DH.encrypt(sessionKey, els.plain.value);
      els.cipher.value = JSON.stringify(payload);
      setStatus('Encryption succeeded. Ciphertext ready.', 'ok');
    }catch(err){
      console.error(err);
      setStatus('Encryption failed: ' + err.message, 'err');
    }
  });

  // Decrypt
  els.decryptBtn.addEventListener('click', async ()=>{
    try{
      if (!sessionKey) throw new Error('Session key is not established');
      let payload; try { payload = JSON.parse(els.cipher.value.trim()); } catch { throw new Error('Ciphertext is not valid JSON'); }
      els.plain.value = await DH.decrypt(sessionKey, payload);
      setStatus('Decryption succeeded.', 'ok');
    }catch(err){
      console.error(err);
      setStatus('Decryption failed: ' + err.message, 'err');
    }
  });

  // Defaults
  enableAfterKeys(false);
  enableSession(false);
}

window.addEventListener('DOMContentLoaded', () => {
  if (!window.crypto || !window.crypto.subtle) {
    const warn = document.getElementById('compat-warning');
    if (warn) warn.style.display = 'block';
  }
  setupPage();
});
