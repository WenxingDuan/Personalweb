// Simple ECDH (P-256) + AES-GCM helper for copy/paste key exchange
// Educational/demo purpose only. Do not use as-is for production security.

const DH = (() => {
  const curve = 'P-256';
  const algoECDH = { name: 'ECDH', namedCurve: curve };

  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  // Utils
  const bufToB64 = (buf) => {
    const bytes = new Uint8Array(buf);
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

  // Key generation and exchange
  async function generateKeyPair() {
    const kp = await crypto.subtle.generateKey(
      algoECDH,
      true, // extractable to allow export and fingerprint
      ['deriveKey', 'deriveBits']
    );
    return kp;
  }

  async function exportPublicJwk(publicKey) {
    const jwk = await crypto.subtle.exportKey('jwk', publicKey);
    // Keep only useful fields for compactness
    const minimal = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, ext: true }; // ext for import
    return minimal;
  }

  async function importPeerPublicJwk(jwk) {
    if (!jwk || jwk.kty !== 'EC') throw new Error('Invalid JWK public key');
    return crypto.subtle.importKey(
      'jwk', jwk, algoECDH, true, []
    );
  }

  async function deriveAesKey(myPrivateKey, peerPublicKey) {
    // Derive a 256-bit AES-GCM key directly from ECDH secret
    const key = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: peerPublicKey },
      myPrivateKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    return key;
  }

  // Encryption / Decryption
  async function encrypt(aesKey, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = textEncoder.encode(plaintext);
    const ctBuf = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aesKey, data);
    return {
      v: 1,
      alg: 'ECDH-P256/AES-GCM-256',
      iv: bufToB64(iv),
      ct: bufToB64(ctBuf)
    };
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

  return {
    generateKeyPair,
    exportPublicJwk,
    importPeerPublicJwk,
    deriveAesKey,
    encrypt,
    decrypt,
    keyFingerprint
  };
})();

// Page wiring
function setupPage(role) {
  const els = Object.fromEntries(Array.from(document.querySelectorAll('[data-id]')).map(e=>[e.dataset.id,e]));

  // Set titles
  document.title = role === 'sender' ? 'Sender · ECDH Key Exchange Demo' : 'Receiver · ECDH Key Exchange Demo';
  els.roleTitle.textContent = role === 'sender' ? 'Sender' : 'Receiver';

  let myKeys = /** @type {CryptoKeyPair|null} */(null);
  let sessionKey = /** @type {CryptoKey|null} */(null);

  function setStatus(msg, cls=''){
    els.status.textContent = msg;
    els.status.className = `muted ${cls}`.trim();
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

  // Generate my key pair
  els.genBtn.addEventListener('click', async ()=>{
    try{
      setStatus('Generating key pair…');
      myKeys = await DH.generateKeyPair();
      const jwk = await DH.exportPublicJwk(myKeys.publicKey);
      els.myPub.value = JSON.stringify(jwk, null, 2);
      enableAfterKeys(true);
      setStatus('Key pair generated. Send your public key to the peer.', 'ok');
    }catch(err){
      console.error(err);
      setStatus('Generation failed: ' + err.message, 'err');
    }
  });

  // Copy my public key
  els.copyMyPub.addEventListener('click', async ()=>{
    try{
      await navigator.clipboard.writeText(els.myPub.value.trim());
      setStatus('Public key copied.', 'ok');
    }catch{
      setStatus('Copy failed, please copy manually.', 'warn');
    }
  });

  // Build session key from peer public key
  els.buildSessionBtn.addEventListener('click', async ()=>{
    try{
      if (!myKeys) throw new Error('Generate your key pair first');
      const peerStr = els.peerPub.value.trim();
      if (!peerStr) throw new Error('Paste peer public key (JWK JSON)');
      let jwk;
      try { jwk = JSON.parse(peerStr); } catch { throw new Error('Peer public key is not valid JSON'); }
      const peerPub = await DH.importPeerPublicJwk(jwk);
      sessionKey = await DH.deriveAesKey(myKeys.privateKey, peerPub);
      const fp = await DH.keyFingerprint(sessionKey);
      els.fingerprint.value = fp;
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
      const pt = els.plain.value;
      const payload = await DH.encrypt(sessionKey, pt);
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
      const ctStr = els.cipher.value.trim();
      let payload;
      try { payload = JSON.parse(ctStr); } catch { throw new Error('Ciphertext is not valid JSON'); }
      const pt = await DH.decrypt(sessionKey, payload);
      els.plain.value = pt;
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
  const role = document.body.getAttribute('data-role') || 'sender';
  // Quick feature check
  if (!window.crypto?.subtle) {
    const warn = document.getElementById('compat-warning');
    if (warn) warn.style.display = 'block';
  }
  setupPage(role);
});
