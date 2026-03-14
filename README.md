# JWT Shield Debugger

> **Security-first JWT analysis — entirely in your browser.**

JWT Shield Debugger is a professional single-page application for decoding, inspecting, and auditing JSON Web Tokens. Unlike generic JWT tools, it is built around a **security audit engine** that automatically flags vulnerabilities and misconfigurations on every token you paste.

---

## Privacy Guarantee

| Property | Detail |
|---|---|
| **Client-side only** | All decoding, parsing, and verification runs in the browser. |
| **Zero data transmission** | No `fetch`, no `XMLHttpRequest`, no WebSocket. Tokens never leave your machine. |
| **No server, no logs** | There is no backend. Nothing is stored. |
| **Web Crypto API** | Signature verification uses the browser's native cryptography, not third-party code. |
| **No frameworks** | Vanilla ES6+ JavaScript — no hidden dependencies that could exfiltrate data. |

The only external resource loaded is the Google Fonts stylesheet for DM Sans and JetBrains Mono. Font files can be self-hosted to achieve full offline operation (see [Self-Hosting Fonts](#self-hosting-fonts)).

---

## Features

### Visual Decoding
- Splits the JWT into **Header · Payload · Signature** with distinct colour coding.
- Renders Header and Payload as **syntax-highlighted JSON** (keys, strings, numbers, booleans, null).
- Shows algorithm, claim list, and signature verification status at a glance.

### Security Audit Engine

The audit engine runs **automatically** on every token and classifies findings into four severity levels:

| Level | Colour | Meaning |
|---|---|---|
| **CRITICAL** | 🔴 `#f87171` | Immediate exploitability; token must be rejected |
| **HIGH** | 🟠 `#fb923c` | Significant risk requiring urgent remediation |
| **MEDIUM** | 🟡 `#facc15` | Moderate risk or best-practice violation |
| **INFO / PASS** | 🔵 / 🟢 | Informational note or check passed |

#### Checks Performed

| ID | Severity | Description |
|---|---|---|
| **Algorithm "none" Attack** | CRITICAL | Flags `alg: none` (any casing) — disables signature verification |
| **Symmetric Algorithm (HS\*)** | INFO | Notes HMAC usage and secret management risks |
| **Non-Standard Algorithm** | MEDIUM | Flags algorithms outside RFC 7518 |
| **Token Expired** | CRITICAL | `exp` is in the past |
| **Token Expiring Soon** | MEDIUM | `exp` is within 5 minutes |
| **Excessive Token Lifetime** | MEDIUM | `exp` is more than 1 year in the future |
| **Missing `exp` Claim** | HIGH | Token has no expiry — valid forever |
| **Token Not Yet Valid (`nbf`)** | CRITICAL | Current time is before `nbf` |
| **Missing `aud` Claim** | MEDIUM | No audience restriction — confused deputy risk |
| **Overly Broad Audience** | HIGH | `aud` is `*`, `any`, or empty |
| **Missing `iss` Claim** | MEDIUM | No issuer — cross-issuer confusion risk |
| **Missing `jti` Claim** | INFO | No unique ID — replay attacks harder to detect |
| **Elevated Privilege Flag** | HIGH | `admin: true`, `sudo: true`, `is_admin: true`, etc. |
| **Elevated Role** | HIGH | `role: admin/superuser/root/owner`, etc. |
| **Wildcard Scope** | CRITICAL | `scope: *`, `permissions: ["*"]`, `admin:*`, etc. |
| **Sensitive Data in Payload** | HIGH | Keys like `password`, `secret`, `api_key` in payload |

### Signature Verification

Local signature verification using the **Web Crypto API** — the browser's native, hardware-backed cryptography:

| Algorithm Family | Algorithms Supported |
|---|---|
| HMAC | HS256, HS384, HS512 |
| RSA-PKCS#1 v1.5 | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| ECDSA | ES256 (P-256), ES384 (P-384), ES512 (P-521) |

For HMAC tokens, paste the secret string. For RSA/EC tokens, paste the PEM-formatted public key.

---

## Getting Started

### Option 1 — Open Directly

```
git clone https://github.com/your-username/jwt-shield.git
cd jwt-shield
open index.html        # macOS
# or: start index.html  (Windows)
# or: xdg-open index.html (Linux)
```

No build step, no `npm install`. Open `index.html` in any modern browser.

### Option 2 — GitHub Pages

1. Push the repository to GitHub.
2. Go to **Settings → Pages**.
3. Set **Source** to the `main` branch, root directory.
4. Your tool will be live at `https://<username>.github.io/jwt-shield/`.

### Option 3 — Any Static Host

Drop the three files (`index.html`, `styles.css`, `app.js`) into any static hosting provider (Netlify, Vercel, Cloudflare Pages, S3, etc.). No server-side configuration required.

---

## File Structure

```
jwt-shield/
├── index.html    # Application shell & HTML structure
├── styles.css    # Dark SecOps theme (CSS custom properties)
├── app.js        # JWT parser, audit engine, Web Crypto verifier
└── README.md     # This file
```

---

## Security Architecture

```
Browser Memory Only
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   Paste JWT  →  Parser  →  Audit Engine  →  Renderer   │
│                                  │                      │
│                          Web Crypto API                 │
│                        (signature verify)               │
│                                                         │
│   ╳  No fetch()    ╳  No XHR    ╳  No WebSocket       │
│   ╳  No backend    ╳  No logs   ╳  No storage          │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

The parser uses `atob()` and `JSON.parse()` — standard browser APIs with no network access. Signature verification uses `window.crypto.subtle` — the W3C Web Cryptography API, available in all modern browsers without any polyfill.

---

## Self-Hosting Fonts

To achieve **full offline operation** with no external requests of any kind:

1. Download [DM Sans](https://fonts.google.com/specimen/DM+Sans) and [JetBrains Mono](https://www.jetbrains.com/lp/mono/) font files.
2. Place the `.woff2` files in a `fonts/` directory alongside `index.html`.
3. Replace the `<link>` Google Fonts tag in `index.html` with `<link rel="stylesheet" href="fonts/fonts.css">`.
4. Create `fonts/fonts.css` with `@font-face` declarations pointing to your local files.

---

## Browser Compatibility

| Browser | Minimum Version |
|---|---|
| Chrome / Edge | 60+ |
| Firefox | 57+ |
| Safari | 11+ |

All features rely exclusively on standard Web APIs (`atob`, `JSON`, `crypto.subtle`, `TextEncoder`). No polyfills are required for modern browsers.

---

## Threat Models This Tool Helps Identify

- **Algorithm Confusion Attack (CVE class)** — `alg: none` or algorithm substitution bypasses signature verification.
- **JWT Secret Brute-forcing** — Weak HMAC secrets can be cracked; tool flags HS* usage.
- **Privilege Escalation via Claim Manipulation** — Elevated admin/role/scope claims are highlighted.
- **Token Replay Attacks** — Missing `jti` makes replay detection impossible; flagged.
- **Confused Deputy Problem** — Missing or wildcard `aud` allows cross-service token forwarding.
- **Indefinite Token Validity** — Missing `exp` means compromised tokens never expire.
- **PII/Secret Exposure** — Sensitive data stored in the (unencrypted) payload is flagged.

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request for significant changes.

All contributions must maintain the core privacy guarantee: **no JWT data may ever be transmitted outside the browser**.

---

## License

MIT © 2026 Or Chetrit — see [`LICENSE`](LICENSE) for details.

---

*JWT Shield Debugger is provided for educational and defensive security purposes. It performs read-only, local analysis only.*
