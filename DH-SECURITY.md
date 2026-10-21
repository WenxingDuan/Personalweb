# DH v2: security, protocol, and deployment

This page is a temporary, manual text-exchange tool built with native WebCrypto. It uses P-256 ECDH, HKDF-SHA-256, and AES-256-GCM without runtime dependencies. P-256 provides approximately 128-bit classical security. Using standard primitives does **not** make this custom protocol independently audited, certified, or post-quantum secure. Obtain an independent protocol and implementation review before relying on it for high-assurance production communications.

## Safe operation and threat model

1. Open a trusted copy on a dedicated HTTPS origin. Each person generates a new handshake and sends the complete handshake JSON to the other person.
2. Paste the other person's handshake and establish the session. Contact that person through an **independent, already trusted channel**, such as an in-person conversation, and compare **all 64 hexadecimal characters** of the displayed safety code. Sending the code through the same untrusted channel as the handshake does not authenticate the session.
3. Both people explicitly confirm the full comparison on their own devices before sending messages. If the codes differ, select “Codes differ — end session” and investigate through the trusted channel. The page cannot prove that a human actually compared the codes or that the peer clicked confirmation.
4. Copy complete ciphertext JSON between the two pages. Each message can be accepted once. The recipient can accept out-of-order messages within the latest 128 sequence positions; sufficiently old messages are rejected even if never previously received.
5. End and clear the session when finished. Refreshing, leaving, browser history restoration, changing the peer handshake, and generating a new handshake discard old session access. Switching tabs does not end the session. Clipboard contents and ciphertext copied elsewhere are outside the page's cleanup boundary.

The intended protections are confidentiality and integrity against an attacker who observes, alters, injects, reorders, or replays exchanged text, **provided the complete safety code is correctly checked**. Active intermediaries cannot be detected without that external authentication step. Denial of service, message length/timing and participant metadata, and mistakes or disclosure by either participant are not prevented. This is not an account identity system, persistent conversation, group protocol, or delivery receipt system.

Private ECDH keys and AES keys are non-exportable WebCrypto keys. ECDH private-key references and intermediate shared-secret buffers are released after derivation. No keys, plaintext, or session counters are intentionally written to browser storage. JavaScript and browser memory management cannot guarantee physical erasure of all copies. The page cannot protect secrets from a compromised device, browser, extension, operating system, hosting origin, release pipeline, or modified page/script. Non-exportability does not stop malicious same-page code from using a live key.

There is no ratchet: a compromise of an active directional AES key exposes captured messages protected by that key. An ended session cannot be recovered through this tool; there is no private-key import/export, backup, session resume, or v1 compatibility.

## Wire protocol

All protocol text is UTF-8 JSON. Every packet has exactly the documented fields and types; unsupported versions, suites, additional fields, malformed encodings, and old JWK/v1 formats are rejected. Binary fields use canonical unpadded Base64url (the `A-Z a-z 0-9 - _` alphabet). Whitespace and property ordering in the incoming JSON do not change the cryptographic transcript. No supplied IV is accepted.

The fixed suite identifier is `P256-HKDF-SHA256-A256GCM`.

### Handshake and derivation

Handshake fields are `{v, suite, pub, nonce}`:

- `v` is the number `2`; `suite` is the identifier above.
- `pub` encodes the 65-byte uncompressed P-256 point (`0x04 || X || Y`), validated by WebCrypto when imported. Both public keys must be different.
- `nonce` encodes 32 fresh random bytes. Each local handshake is generated from a new P-256 key pair and can participate in derivation only once.

Compare public-key byte arrays lexicographically as unsigned bytes. The smaller key is role `a`, the larger is role `b`. Let `a` and `b` refer to their complete handshake packets. The exact transcript is:

```js
UTF8(JSON.stringify(['DH-v2', suite, [a.pub, a.nonce], [b.pub, b.nonce]]))
```

Compute `hash = SHA256(transcript)` and `sid = Base64url(hash)`. Derive the 256-bit P-256 ECDH shared secret, import it as a non-exportable HKDF key, and use HKDF-SHA-256 with `salt = hash`. The following UTF-8 `info` labels separate purposes:

| HKDF info | Output | Use |
| --- | --- | --- |
| `DH-v2/a-to-b` | 256-bit AES-GCM key | Role `a` encrypts; role `b` decrypts |
| `DH-v2/b-to-a` | 256-bit AES-GCM key | Role `b` encrypts; role `a` decrypts |
| `DH-v2/verify` | 256 bits | Full 64-character hexadecimal safety code, displayed in groups |

The directional AES keys are non-exportable and receive only the local operation's required usage. The safety code is a separate HKDF output, not an export or hash of an AES key. Neither encryption nor decryption is permitted until the local user confirms verification.

### Messages and replay protection

Ciphertext fields are `{v, suite, sid, from, seq, ct}`:

- `v`, `suite`, and `sid` must identify this v2 session.
- `from` is the sender's role, `a` or `b`; a page only decrypts the peer's direction.
- `seq` is an integer JSON number from `0` through `65535`.
- `ct` is Base64url of ciphertext followed by the 16-byte GCM authentication tag.

The 12-byte GCM nonce is four zero bytes followed by the sequence number encoded as an unsigned, eight-byte, big-endian integer. Tag length is 128 bits. The exact authenticated additional data is:

```js
UTF8(JSON.stringify([2, suite, sid, from, seq]))
```

Each sender synchronously reserves its next sequence number before awaiting encryption, and never rolls it back on failure. The two directions use different keys. Re-establishment requires a new handshake and key pair, so a counter cannot restart under an old key.

The recipient maintains a 128-bit sliding replay window. Authentication must succeed before updating the window or received-byte budget; duplicate concurrent decryptions cannot both commit. A failed authentication cannot advance the window and block authentic earlier messages. Asynchronous operations check the session generation before committing results, so reset or replacement cannot restore an old session or old plaintext.

### Limits and session lifecycle

| Limit | Value |
| --- | --- |
| Handshake JSON | 4 KiB |
| Plaintext per message | 1 MiB, measured as UTF-8 bytes |
| Ciphertext JSON | 1.5 MiB |
| Messages per direction | 65,536 |
| Plaintext total per direction | 64 MiB |
| Session lifetime | One hour from generating the local handshake |
| Receive window | Latest 128 sequence positions |

The application preserves valid plaintext, including empty strings, Unicode, line breaks, a leading BOM, and control characters; it does not silently sanitize it. An unpaired UTF-16 surrogate is rejected instead of being silently replaced during UTF-8 encoding. Oversized or malformed packets are rejected before cryptographic processing. Oversized individual input can be corrected and retried; exceeding a cumulative session budget ends the entire session. Generate and verify fresh handshakes when the session reaches its message, byte, or time budget. Failed sends do not reclaim sequence numbers and may require renewal sooner. Each local handshake is consumed once when establishing a session; a failed establishment, including an invalid peer handshake, requires new keys.

The visible states are not generated, awaiting exchange, awaiting verification, ready, and ended. Regeneration, peer changes, mismatch, and explicit ending revoke verification and old keys. Initial load, page departure, and back/forward-cache restoration clear sensitive fields. Each endpoint uses its own deadline, beginning when it generates the local handshake; establishment does not reset that deadline. Expiry is also checked by the cryptographic operations, so throttled background timers do not extend permission to use an expired session.

## Deployment requirements

Use a **dedicated origin**, such as `https://secure-chat.example.com`, with only this application's reviewed static assets. A path on a shared origin is not isolation: other same-origin scripts and service workers can compromise the page. Do not add analytics, advertising, third-party scripts, remote fonts, storage, service workers, or unrelated applications. If the origin has hosted a service worker, remove the registration and clear affected browser site data before trusting it; preferably start with a new origin. Do not serve the repository or development files wholesale.

Serve `DH.html`, `js/dh.js`, `style.css`, and the optional favicon with correct MIME types. Deploy reviewed versions together, including `DH-SECURITY.md` if retaining the guide link. Protect source, hosting credentials, and the release process. CSP is defense in depth and cannot make an attacker-controlled server trustworthy.

Configure these **actual HTTP response headers** on the deployment, including error responses where applicable:

```http
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; frame-ancestors 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
Cache-Control: no-store
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
```

Redirect HTTP to HTTPS at the server, using a valid certificate. HSTS takes effect over HTTPS; only add `includeSubDomains` or preload after assessing every affected subdomain. Apply `Cache-Control: no-store` to HTML, JavaScript, and CSS so returning users receive the reviewed current version. Avoid broad CORS access. Ensure hosting middleware does not inject scripts or loosen these policies.

The page's CSP meta tag limits resources but **cannot enforce `frame-ancestors`**, and HTML meta cannot replace the response headers above. `frame-src 'none'` controls what this page embeds, not which pages may embed it. Validate the real headers in browser developer tools and verify an attempted cross-origin iframe is blocked after deployment. The repository changes do not themselves configure a host or prove these headers are active.

For local development only, serve the directory using an existing static server bound to the loopback interface, for example:

```sh
python -m http.server 8000 --bind 127.0.0.1
```

Open `http://127.0.0.1:8000/DH.html`. Localhost or loopback HTTP is accepted for development when the browser treats it as a secure context; ordinary HTTP, `file:`, missing WebCrypto, or missing required algorithms leave cryptographic operations disabled. The development server does not supply the production security headers above.

## Verification

Run the dependency-free checks with a supported Node.js version that provides WebCrypto:

```sh
node --test
```

The tests exercise interoperability, required verification, non-exportable keys, authenticated metadata, malformed/oversized inputs, replay windows, concurrent duplicates, failed-send nonce reservation, session replacement, and lifetime/resource limits.

Before release, exercise two real browser pages: exchange and compare handshakes, verify both sides, send both directions, replay and alter ciphertext, regenerate during pending operations, reject verification, and test empty/Unicode/multiline text. Verify refresh, departure, and browser back/forward cannot restore plaintext or keys; clipboard denial should offer manual copying. Inspect network activity: only local static assets should load, with no message or key data sent. Test `file:`, insecure non-loopback HTTP, and an unsupported browser; operations must remain disabled. Finally verify production HTTPS, response headers, iframe blocking, and origin isolation on the actual deployment.
