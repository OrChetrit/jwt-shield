/**
 * JWT Shield Debugger — app.js
 *
 * Pure client-side JWT security analysis tool.
 * Zero external calls. All processing in-memory.
 * Signature verification via the Web Crypto API.
 *
 * Architecture:
 *   1. Base64url utilities
 *   2. JWT parser
 *   3. Security audit engine
 *   4. Signature verifier  (Web Crypto API, async)
 *   5. Syntax highlighter
 *   6. UI renderer
 *   7. Event handlers & init
 */

'use strict';

// ══════════════════════════════════════════════════════════════
// 1. CONSTANTS
// ══════════════════════════════════════════════════════════════

const SEV = Object.freeze({
  CRITICAL: 'critical',
  HIGH:     'high',
  MEDIUM:   'medium',
  INFO:     'info',
  PASS:     'pass',
});

const SEV_ORDER = { critical: 0, high: 1, medium: 2, info: 3, pass: 4 };

/** Elevated admin-style claim keys to flag */
const ADMIN_CLAIM_KEYS = [
  'admin', 'is_admin', 'isAdmin', 'administrator',
  'sudo', 'root', 'superuser', 'is_superuser', 'isSuperuser',
  'is_root', 'isRoot',
];

/** Role values considered dangerous */
const ELEVATED_ROLES = [
  'admin', 'administrator', 'superuser', 'super_admin', 'superadmin',
  'root', 'system', 'owner', 'god', 'staff', 'internal',
];

/** Algorithm families */
const HMAC_ALGS  = ['HS256', 'HS384', 'HS512'];
const RSA_ALGS   = ['RS256', 'RS384', 'RS512'];
const ECDSA_ALGS = ['ES256', 'ES384', 'ES512'];
const PSS_ALGS   = ['PS256', 'PS384', 'PS512'];

const HASH_MAP = {
  HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512',
  RS256: 'SHA-256', RS384: 'SHA-384', RS512: 'SHA-512',
  ES256: 'SHA-256', ES384: 'SHA-384', ES512: 'SHA-512',
  PS256: 'SHA-256', PS384: 'SHA-384', PS512: 'SHA-512',
};

const EC_CURVE = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' };
const EC_SIG_SIZE = { ES256: 32, ES384: 48, ES512: 66 };
const PSS_SALT = { PS256: 32, PS384: 48, PS512: 64 };


// ══════════════════════════════════════════════════════════════
// 2. BASE64URL UTILITIES
// ══════════════════════════════════════════════════════════════

/**
 * Decode a base64url string to a plain string.
 * Handles missing padding automatically.
 */
function b64uDecode(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad  = (4 - (b64.length % 4)) % 4;
  return atob(b64 + '='.repeat(pad));
}

/** Decode base64url → Uint8Array */
function b64uToBytes(str) {
  const bin = b64uDecode(str);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

/** Decode base64url → parsed JSON */
function b64uToJSON(str) {
  try {
    return JSON.parse(b64uDecode(str));
  } catch (e) {
    throw new Error(`Failed to decode base64url segment: ${e.message}`);
  }
}

/** Encode a plain JS object to base64url (for sample token generation) */
function objToB64u(obj) {
  return btoa(JSON.stringify(obj))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/** Convert PEM-formatted key to an ArrayBuffer */
function pemToBuffer(pem) {
  const b64 = pem
    .replace(/-----(?:BEGIN|END)[^-]+-----/g, '')
    .replace(/\s/g, '');
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

/**
 * JWTs use raw IEEE P1363 for ECDSA (r‖s), but some libraries produce DER.
 * If the byte array length doesn't match P1363 size, attempt DER→P1363 conversion.
 */
function normaliseEcSig(bytes, alg) {
  const size = EC_SIG_SIZE[alg] || 32;
  if (bytes.length === size * 2) return bytes; // Already P1363

  // Try to parse DER SEQUENCE { INTEGER r, INTEGER s }
  try {
    let off = 0;
    if (bytes[off++] !== 0x30) return bytes;
    let seqLen = bytes[off++];
    if (seqLen & 0x80) off += seqLen & 0x7f;

    const readInt = () => {
      if (bytes[off++] !== 0x02) return null;
      let len = bytes[off++];
      if (len & 0x80) {
        const n = len & 0x7f; len = 0;
        for (let i = 0; i < n; i++) len = (len << 8) | bytes[off++];
      }
      const v = bytes.slice(off, off + len); off += len; return v;
    };

    const r = readInt(); const s = readInt();
    if (!r || !s) return bytes;

    const result = new Uint8Array(size * 2);
    const trim = v => v[0] === 0 ? v.slice(1) : v;
    const rT = trim(r); const sT = trim(s);
    result.set(rT, size - rT.length);
    result.set(sT, size * 2 - sT.length);
    return result;
  } catch { return bytes; }
}


// ══════════════════════════════════════════════════════════════
// 3. JWT PARSER
// ══════════════════════════════════════════════════════════════

/**
 * Parse a raw JWT string into its constituent parts.
 * @returns {{ raw, parts, header, payload, signingInput, signature }}
 * @throws {Error} on malformed input
 */
function parseJWT(raw) {
  const token = raw.trim();
  if (!token) throw new Error('Empty input');

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(
      parts.length < 3
        ? `Incomplete JWT: found ${parts.length} part(s), expected 3`
        : `Malformed JWT: found ${parts.length} parts (dots) — expected exactly 3`
    );
  }

  const [headerB64, payloadB64, sigB64] = parts;

  return {
    raw:          token,
    parts:        parts,
    header:       b64uToJSON(headerB64),
    payload:      b64uToJSON(payloadB64),
    signingInput: `${headerB64}.${payloadB64}`,
    signature:    sigB64,
  };
}


// ══════════════════════════════════════════════════════════════
// 4. SECURITY AUDIT ENGINE
// ══════════════════════════════════════════════════════════════

/** Format seconds into a human-readable duration string */
function fmtDuration(secs) {
  const abs = Math.abs(secs);
  if (abs < 60)       return `${abs}s`;
  if (abs < 3600)     return `${Math.round(abs / 60)}m`;
  if (abs < 86400)    return `${Math.round(abs / 3600)}h`;
  if (abs < 2592000)  return `${Math.round(abs / 86400)}d`;
  if (abs < 31536000) return `${Math.round(abs / 2592000)} months`;
  return `${(abs / 31536000).toFixed(1)} years`;
}

/** Format a Unix timestamp to a locale-aware ISO-like string */
function fmtTime(ts) {
  return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

/**
 * Run all security checks on the decoded JWT.
 * Returns an array of finding objects sorted by severity.
 */
function runAudit(jwt) {
  const findings = [];
  const { header, payload } = jwt;
  const now = Math.floor(Date.now() / 1000);

  // ── A. Algorithm checks ──────────────────────────────────────
  const alg = (header.alg ?? '').toString();
  const algUpper = alg.toUpperCase();

  if (!alg || algUpper === 'NONE') {
    findings.push({
      severity:   SEV.CRITICAL,
      title:      'Algorithm "none" Attack Vector',
      desc:       `The \`alg\` header is "${alg || '(missing)'}". This disables signature verification entirely — any party can forge a valid-looking token by manipulating the payload and setting alg to "none".`,
      rec:        'Reject tokens with alg=none at the server. Enforce a strict allowlist of accepted algorithms (e.g. RS256, ES256). Never trust the algorithm declared in the token header.',
    });
  } else if (algUpper === 'HS256' || algUpper === 'HS384' || algUpper === 'HS512') {
    findings.push({
      severity: SEV.INFO,
      title:    `Symmetric Algorithm (${alg})`,
      desc:     `HMAC algorithms use the same key for signing and verification. If the verifier is a public service, a weak or exposed secret allows signature forgery.`,
      rec:      'Ensure the HMAC secret is cryptographically random, at least 256 bits, and stored securely. Consider RS256 or ES256 for distributed systems where the verifier shouldn\'t hold the signing key.',
    });
  } else if ([...RSA_ALGS, ...ECDSA_ALGS, ...PSS_ALGS].includes(algUpper)) {
    findings.push({
      severity: SEV.PASS,
      title:    `Asymmetric Algorithm (${alg})`,
      desc:     `Asymmetric algorithms allow public key distribution for verification while keeping the private key confidential.`,
      rec:      'Ensure the private signing key is securely stored, rotated periodically, and never exposed.',
    });
  } else {
    findings.push({
      severity: SEV.MEDIUM,
      title:    `Non-Standard Algorithm: ${alg}`,
      desc:     `The algorithm "${alg}" is not a standard JWT algorithm (RFC 7518). Some non-standard algorithms have known implementation flaws.`,
      rec:      'Use only well-vetted algorithms from RFC 7518: RS256, ES256, HS256, or their SHA-384/512 variants.',
    });
  }

  // ── B. Expiration (exp) ──────────────────────────────────────
  if (payload.exp == null) {
    findings.push({
      severity: SEV.HIGH,
      title:    'Missing Expiration Claim (exp)',
      desc:     'No `exp` claim is present. This token never expires — if it is stolen or leaked, it remains valid indefinitely.',
      rec:      'Always include an `exp` claim. Use short-lived access tokens (≤ 15 minutes for sensitive ops) and implement refresh token rotation.',
    });
  } else {
    const diff = payload.exp - now;
    if (diff < 0) {
      findings.push({
        severity: SEV.CRITICAL,
        title:    'Token Expired',
        desc:     `Token expired ${fmtDuration(-diff)} ago (${fmtTime(payload.exp)}). Any server accepting this token is vulnerable to replay with stale credentials.`,
        rec:      'This token must be rejected. Obtain a fresh token via your authentication flow.',
      });
    } else if (diff <= 300) {
      findings.push({
        severity: SEV.MEDIUM,
        title:    'Token Expiring Soon',
        desc:     `Token expires in ${fmtDuration(diff)} (${fmtTime(payload.exp)}). Automations relying on this token may fail shortly.`,
        rec:      'Proactively refresh the token before expiry using your refresh token endpoint.',
      });
    } else if (diff > 365 * 24 * 3600) {
      findings.push({
        severity: SEV.MEDIUM,
        title:    'Excessive Token Lifetime',
        desc:     `Token is valid for ${fmtDuration(diff)} (expires ${fmtTime(payload.exp)}). Long-lived tokens significantly increase the blast radius of a compromise.`,
        rec:      'Use short-lived access tokens (minutes to hours). For long-lived sessions, use opaque refresh tokens stored securely.',
      });
    } else {
      findings.push({
        severity: SEV.PASS,
        title:    'Expiration Is Valid',
        desc:     `Token expires at ${fmtTime(payload.exp)} (in ${fmtDuration(diff)}).`,
        rec:      '',
      });
    }
  }

  // ── C. Not Before (nbf) ──────────────────────────────────────
  if (payload.nbf != null) {
    const diff = now - payload.nbf;
    if (diff < 0) {
      findings.push({
        severity: SEV.CRITICAL,
        title:    'Token Not Yet Valid (nbf)',
        desc:     `Token is not valid until ${fmtTime(payload.nbf)} (${fmtDuration(-diff)} from now). Accepting it now violates the JWT spec and may indicate a clock-skew misconfiguration or replay attack attempt.`,
        rec:      'Reject tokens where current time is before `nbf`. Allow small clock-skew tolerance (≤ 30s) but no more.',
      });
    } else {
      findings.push({
        severity: SEV.PASS,
        title:    'Not-Before Claim Valid',
        desc:     `Token became valid at ${fmtTime(payload.nbf)}.`,
        rec:      '',
      });
    }
  }

  // ── D. Audience (aud) ────────────────────────────────────────
  if (payload.aud == null) {
    findings.push({
      severity: SEV.MEDIUM,
      title:    'Missing Audience Claim (aud)',
      desc:     'No `aud` claim. Without audience validation, this token could be forwarded to and accepted by unintended services ("confused deputy" attack).',
      rec:      'Add a specific `aud` claim and validate it on every relying party. Reject tokens with unexpected audience values.',
    });
  } else {
    const audArr = [].concat(payload.aud);
    const hasWildcard = audArr.some(a => a === '*' || a === '' || a === 'any');
    if (hasWildcard) {
      findings.push({
        severity: SEV.HIGH,
        title:    'Overly Broad Audience',
        desc:     `The \`aud\` claim contains a wildcard or empty value: \`${JSON.stringify(payload.aud)}\`. This token is valid for any service, defeating audience restriction entirely.`,
        rec:      'Use specific, named audience identifiers (e.g. "api.payments.example.com"). Never use wildcards.',
      });
    } else {
      findings.push({
        severity: SEV.PASS,
        title:    'Audience Specified',
        desc:     `aud: ${JSON.stringify(payload.aud)}`,
        rec:      'Ensure each relying party verifies the aud value matches its own identifier.',
      });
    }
  }

  // ── E. Issuer (iss) ──────────────────────────────────────────
  if (!payload.iss) {
    findings.push({
      severity: SEV.MEDIUM,
      title:    'Missing Issuer Claim (iss)',
      desc:     'No `iss` claim. Without issuer validation, relying parties cannot confirm where the token originated, enabling cross-issuer token confusion.',
      rec:      'Add an `iss` claim and validate it against a known allowlist on every relying party.',
    });
  }

  // ── F. JWT ID (jti) ──────────────────────────────────────────
  if (!payload.jti) {
    findings.push({
      severity: SEV.INFO,
      title:    'Missing JWT ID (jti)',
      desc:     'No unique `jti` identifier. Without it, replay attacks are difficult to detect since identical tokens cannot be distinguished.',
      rec:      'Add a `jti` claim (e.g., a UUID). For high-value operations, maintain a short-lived blocklist and reject any reuse of the same jti.',
    });
  }

  // ── G. Elevated privilege claims ─────────────────────────────
  const elevatedFound = [];
  for (const key of ADMIN_CLAIM_KEYS) {
    const val = payload[key];
    if (val === true || val === 1 || val === 'true' || val === '1') {
      elevatedFound.push(`"${key}": ${JSON.stringify(val)}`);
    }
  }
  if (elevatedFound.length > 0) {
    findings.push({
      severity: SEV.HIGH,
      title:    'Elevated Privilege Flag',
      desc:     `The payload contains privilege-granting claims: ${elevatedFound.join(', ')}. If signature verification is skipped or the secret is weak, an attacker can forge administrative access.`,
      rec:      'Treat JWT claims as untrusted until the signature is verified with a secure key. Apply authorisation logic server-side, independent of the token when possible.',
    });
  }

  // ── H. Elevated roles ────────────────────────────────────────
  const roleVal = payload.role ?? payload.roles ?? payload.userRole ?? payload.user_role;
  if (roleVal != null) {
    const roleArr = [].concat(roleVal).map(r => String(r).toLowerCase());
    const found   = roleArr.filter(r => ELEVATED_ROLES.some(er => r.includes(er)));
    if (found.length > 0) {
      findings.push({
        severity: SEV.HIGH,
        title:    'Elevated Role Detected',
        desc:     `Role claim contains elevated values: ${found.map(r => `"${r}"`).join(', ')}. Privilege escalation is possible if an attacker can forge or modify this claim.`,
        rec:      'Enforce role authorisation server-side. Validate signatures before trusting any role claim.',
      });
    }
  }

  // ── I. Broad scopes / permissions ────────────────────────────
  const scopeVal = payload.scope ?? payload.scopes ?? payload.permissions ?? payload.scp;
  if (scopeVal != null) {
    const scopeStr = typeof scopeVal === 'string' ? scopeVal : JSON.stringify(scopeVal);
    const dangerousPatterns = [/\*/,  /admin[:\s]write/, /admin[:\s]\*/, /\ball\b/, /full[_\s-]?access/i];
    const matched = dangerousPatterns.filter(p => p.test(scopeStr));
    if (matched.length > 0) {
      findings.push({
        severity: SEV.CRITICAL,
        title:    'Wildcard / Overly-Broad Scope',
        desc:     `The scope/permissions claim contains broad access patterns: \`${scopeStr.slice(0, 120)}\`. This grants unrestricted access across protected resources.`,
        rec:      'Follow the principle of least privilege. Define granular scopes per resource/action (e.g. "read:orders"). Never issue tokens with wildcard scopes.',
      });
    }
  }

  // ── J. Sensitive data in payload ─────────────────────────────
  const sensitiveKeys = ['password', 'passwd', 'secret', 'api_key', 'apikey', 'credit_card', 'ssn', 'token'];
  const sensitiveFound = sensitiveKeys.filter(k =>
    Object.keys(payload).some(pk => pk.toLowerCase().includes(k))
  );
  if (sensitiveFound.length > 0) {
    findings.push({
      severity: SEV.HIGH,
      title:    'Potentially Sensitive Data in Payload',
      desc:     `The payload contains keys that may store sensitive data: ${sensitiveFound.map(k => `"${k}"`).join(', ')}. JWT payloads are only base64-encoded, not encrypted — anyone with the token can read them.`,
      rec:      'Never store secrets, passwords, or PII in a JWT payload unless the token is a JWE (JSON Web Encryption). Use opaque references instead.',
    });
  }

  // Sort findings by severity order, PASS findings go last
  findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  return findings;
}


// ══════════════════════════════════════════════════════════════
// 5. SIGNATURE VERIFIER  (Web Crypto API — async)
// ══════════════════════════════════════════════════════════════

/**
 * Verify a JWT signature using the Web Crypto API.
 * Supports HS*/RS*/ES*/PS* families.
 *
 * @param {string} signingInput  — "headerB64.payloadB64"
 * @param {string} sigB64u       — base64url-encoded signature
 * @param {string} secretOrKey   — HMAC secret or PEM public key
 * @param {string} alg           — e.g. "HS256", "RS256", "ES256"
 * @returns {Promise<boolean>}
 */
async function verifySignature(signingInput, sigB64u, secretOrKey, alg) {
  const algUpper = alg.toUpperCase();

  if (algUpper === 'NONE') {
    throw new Error('Algorithm "none" — there is no signature to verify.');
  }

  const hash = HASH_MAP[algUpper];
  if (!hash) throw new Error(`Unsupported algorithm: ${alg}`);

  const enc  = new TextEncoder();
  const data = enc.encode(signingInput);

  // ── HMAC (HS*) ──────────────────────────────────────────────
  if (HMAC_ALGS.includes(algUpper)) {
    const keyMaterial = enc.encode(secretOrKey);
    const cryptoKey = await crypto.subtle.importKey(
      'raw', keyMaterial,
      { name: 'HMAC', hash },
      false, ['verify']
    );
    const sigBytes = b64uToBytes(sigB64u);
    return crypto.subtle.verify('HMAC', cryptoKey, sigBytes, data);
  }

  // ── RSA-PKCS1-v1_5 (RS*) ───────────────────────────────────
  if (RSA_ALGS.includes(algUpper)) {
    const keyBuf = pemToBuffer(secretOrKey);
    const cryptoKey = await crypto.subtle.importKey(
      'spki', keyBuf,
      { name: 'RSASSA-PKCS1-v1_5', hash },
      false, ['verify']
    );
    const sigBytes = b64uToBytes(sigB64u);
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, sigBytes, data);
  }

  // ── ECDSA (ES*) ─────────────────────────────────────────────
  if (ECDSA_ALGS.includes(algUpper)) {
    const keyBuf = pemToBuffer(secretOrKey);
    const namedCurve = EC_CURVE[algUpper];
    const cryptoKey = await crypto.subtle.importKey(
      'spki', keyBuf,
      { name: 'ECDSA', namedCurve },
      false, ['verify']
    );
    const sigBytes = normaliseEcSig(b64uToBytes(sigB64u), algUpper);
    return crypto.subtle.verify({ name: 'ECDSA', hash }, cryptoKey, sigBytes, data);
  }

  // ── RSA-PSS (PS*) ────────────────────────────────────────────
  if (PSS_ALGS.includes(algUpper)) {
    const keyBuf = pemToBuffer(secretOrKey);
    const cryptoKey = await crypto.subtle.importKey(
      'spki', keyBuf,
      { name: 'RSA-PSS', hash },
      false, ['verify']
    );
    const sigBytes = b64uToBytes(sigB64u);
    return crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength: PSS_SALT[algUpper] },
      cryptoKey, sigBytes, data
    );
  }

  throw new Error(`Unsupported algorithm: ${alg}`);
}


// ══════════════════════════════════════════════════════════════
// 6. SYNTAX HIGHLIGHTER
// ══════════════════════════════════════════════════════════════

/**
 * Convert a JS value to a syntax-highlighted HTML string.
 * Uses safe HTML escaping — no XSS risk.
 */
function syntaxHighlight(val, indent = 0) {
  const esc = s => s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

  const pad = (n) => '  '.repeat(n);

  if (val === null)      return `<span class="syn-null">null</span>`;
  if (val === true)      return `<span class="syn-bool-t">true</span>`;
  if (val === false)     return `<span class="syn-bool-f">false</span>`;
  if (typeof val === 'number') return `<span class="syn-num">${val}</span>`;
  if (typeof val === 'string') return `<span class="syn-str">"${esc(val)}"</span>`;

  if (Array.isArray(val)) {
    if (val.length === 0) return '<span class="syn-punc">[]</span>';
    const items = val.map(v => `${pad(indent + 1)}${syntaxHighlight(v, indent + 1)}`);
    return `<span class="syn-punc">[</span>\n${items.join('<span class="syn-punc">,</span>\n')}\n${pad(indent)}<span class="syn-punc">]</span>`;
  }

  if (typeof val === 'object') {
    const keys = Object.keys(val);
    if (keys.length === 0) return '<span class="syn-punc">{}</span>';
    const pairs = keys.map(k => {
      const keyHtml  = `<span class="syn-key">"${esc(k)}"</span>`;
      const valHtml  = syntaxHighlight(val[k], indent + 1);
      return `${pad(indent + 1)}${keyHtml}<span class="syn-punc">: </span>${valHtml}`;
    });
    return `<span class="syn-punc">{</span>\n${pairs.join('<span class="syn-punc">,</span>\n')}\n${pad(indent)}<span class="syn-punc">}</span>`;
  }

  return esc(String(val));
}


// ══════════════════════════════════════════════════════════════
// 7. UI RENDERER
// ══════════════════════════════════════════════════════════════

/** Show/hide a card element */
const show = el => el.classList.remove('card-hidden');
const hide = el => el.classList.add('card-hidden');

/** Cached DOM references — populated in init() */
let DOM = {};

/** Render the colour-coded token visual */
function renderTokenVisual(parts) {
  const [h, p, s] = parts;
  const maxLen = 420;
  const raw    = `${h}.${p}.${s}`;

  // Truncate long tokens for display
  const displayH = h.length > maxLen ? h.slice(0, maxLen / 3) + '…' : h;
  const displayP = p.length > maxLen ? p.slice(0, maxLen / 3) + '…' : p;
  const displayS = s.length > maxLen ? s.slice(0, maxLen / 3) + '…' : s;

  DOM.tokenVisual.innerHTML =
    `<span class="tv-header">${displayH}</span>` +
    `<span class="tv-dot">.</span>` +
    `<span class="tv-payload">${displayP}</span>` +
    `<span class="tv-dot">.</span>` +
    `<span class="tv-signature">${displayS}</span>`;
}

/** Render the decoded header/payload sections */
function renderDecoded(jwt) {
  DOM.decodedHeader.innerHTML  = syntaxHighlight(jwt.header);
  DOM.decodedPayload.innerHTML = syntaxHighlight(jwt.payload);

  const claims = Object.keys(jwt.payload);
  DOM.claimCount.textContent = `${claims.length} claim${claims.length !== 1 ? 's' : ''}`;

  DOM.metaAlg.textContent     = jwt.header.alg || '(none)';
  DOM.metaClaims.textContent  = claims.join(', ');
}

/** Render security score counters */
function renderScore(findings) {
  const counts = { critical: 0, high: 0, medium: 0, pass: 0 };
  for (const f of findings) {
    if (f.severity === SEV.CRITICAL) counts.critical++;
    else if (f.severity === SEV.HIGH)   counts.high++;
    else if (f.severity === SEV.MEDIUM || f.severity === SEV.INFO) counts.medium++;
    else if (f.severity === SEV.PASS)   counts.pass++;
  }

  DOM.cntCritical.textContent = counts.critical;
  DOM.cntHigh.textContent     = counts.high;
  DOM.cntMedium.textContent   = counts.medium;
  DOM.cntPass.textContent     = counts.pass;

  // Highlight non-zero cells
  DOM.scoreCritical.classList.toggle('active', counts.critical > 0);
  DOM.scoreHigh.classList.toggle('active', counts.high > 0);
  DOM.scoreMedium.classList.toggle('active', counts.medium > 0);
  DOM.scorePass.classList.toggle('active', counts.pass > 0);
}

/** Render security audit findings */
function renderFindings(findings) {
  if (findings.length === 0) {
    DOM.findings.innerHTML = '<p style="padding:1rem 1.125rem;color:var(--text-3);font-size:.8rem;">No findings.</p>';
    return;
  }

  DOM.findings.innerHTML = findings.map(f => {
    const sevClass  = `sev-${f.severity}`;
    const barClass  = `finding-bar-${f.severity}`;
    const sevLabel  = f.severity.toUpperCase();
    const descHtml  = escapeHtml(f.desc).replace(/`([^`]+)`/g, '<code style="font-family:var(--font-mono);font-size:.72em;background:rgba(255,255,255,.07);padding:.1em .3em;border-radius:3px;">$1</code>');
    const recHtml   = f.rec ? `<p class="finding-rec">${escapeHtml(f.rec)}</p>` : '';

    return `
      <div class="finding" role="listitem">
        <div class="finding-bar ${barClass}"></div>
        <div class="finding-body">
          <div class="finding-head">
            <span class="finding-sev ${sevClass}">${sevLabel}</span>
            <span class="finding-title">${escapeHtml(f.title)}</span>
          </div>
          <p class="finding-desc">${descHtml}</p>
          ${recHtml}
        </div>
      </div>`;
  }).join('');
}

/** Escape HTML entities to prevent XSS */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Full UI update after a successful token parse */
function renderAll(jwt, findings) {
  renderTokenVisual(jwt.parts);
  renderDecoded(jwt);
  renderScore(findings);
  renderFindings(findings);

  // Timestamp
  DOM.auditTs.textContent = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

  // Auto-select algorithm in verify dropdown
  const alg = (jwt.header.alg || '').toUpperCase();
  const matchingOpt = [...DOM.verifyAlg.options].find(o => o.value === alg);
  if (matchingOpt) DOM.verifyAlg.value = alg;
  updateKeyHint(alg);

  // Reset verification state
  hide(DOM.verifyResult);
  DOM.metaSig.textContent   = 'Not Verified';
  DOM.metaSig.style.color   = '';

  // Show all result panels, hide empty state
  hide(DOM.emptyState);
  show(DOM.cardBreakdown);
  show(DOM.cardHeader);
  show(DOM.cardPayload);
  show(DOM.cardScore);
  show(DOM.cardAudit);
  show(DOM.cardVerify);
}

/** Reset UI to empty state */
function resetUI() {
  hide(DOM.cardBreakdown);
  hide(DOM.cardHeader);
  hide(DOM.cardPayload);
  hide(DOM.cardScore);
  hide(DOM.cardAudit);
  hide(DOM.cardVerify);
  show(DOM.emptyState);

  DOM.findings.innerHTML    = '';
  DOM.decodedHeader.innerHTML  = '';
  DOM.decodedPayload.innerHTML = '';
  DOM.tokenVisual.innerHTML = '';
  DOM.inputStatus.textContent  = '';
  DOM.inputStatus.className    = 'input-status';
}

/** Update the key hint text based on selected algorithm */
function updateKeyHint(alg) {
  const algUpper = (alg || '').toUpperCase();
  let hint = '';
  if (HMAC_ALGS.includes(algUpper))        hint = 'HMAC secret (UTF-8 string)';
  else if ([...RSA_ALGS, ...PSS_ALGS].includes(algUpper)) hint = 'RSA public key (PEM)';
  else if (ECDSA_ALGS.includes(algUpper))  hint = 'EC public key (PEM)';
  else                                     hint = 'Secret or public key';
  DOM.keyHint.textContent = hint;
}


// ══════════════════════════════════════════════════════════════
// 8. SAMPLE TOKEN GENERATOR
// ══════════════════════════════════════════════════════════════

/**
 * Generate a demo token with multiple security issues pre-baked in.
 * The signature is intentionally invalid (demo only).
 */
function generateSampleToken() {
  const header  = { alg: 'HS256', typ: 'JWT' };
  const now     = Math.floor(Date.now() / 1000);
  const payload = {
    sub:       'usr_7f3a91bc',
    name:      'Jane Admin',
    email:     'jane@example.com',
    iat:       now - 3600,
    exp:       now + 120,          // expires in 2 minutes → "expiring soon"
    admin:     true,               // elevated privilege flag
    role:      'superuser',        // elevated role
    scope:     '*',                // wildcard scope
    aud:       '*',                // wildcard audience
    iss:       'demo.jwt-shield.io',
    // jti intentionally omitted  → missing jti finding
  };

  const h = objToB64u(header);
  const p = objToB64u(payload);
  // Fake (invalid) signature — demo only, cannot pass verification
  const fakeSig = 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  return `${h}.${p}.${fakeSig}`;
}


// ══════════════════════════════════════════════════════════════
// 9. EVENT HANDLERS
// ══════════════════════════════════════════════════════════════

/** Global parsed JWT state (null when no valid token is loaded) */
let currentJWT = null;

/** Debounce timer for the input field */
let debounceTimer = null;

function handleInput() {
  clearTimeout(debounceTimer);
  const raw = DOM.jwtInput.value.trim();

  if (!raw) { resetUI(); return; }

  // Short debounce so we don't audit on every keystroke
  debounceTimer = setTimeout(() => processToken(raw), 180);
}

function processToken(raw) {
  try {
    const jwt     = parseJWT(raw);
    const findings = runAudit(jwt);
    currentJWT     = jwt;

    DOM.inputStatus.className   = 'input-status status-ok';
    DOM.inputStatus.textContent = '✓ Valid JWT structure';

    renderAll(jwt, findings);
  } catch (err) {
    currentJWT = null;
    DOM.inputStatus.className   = 'input-status status-error';
    DOM.inputStatus.textContent = `✗ ${err.message}`;
    resetUI();
    // Keep input visible even in error state
    DOM.inputStatus.className   = 'input-status status-error';
    DOM.inputStatus.textContent = `✗ ${err.message}`;
  }
}

async function handleVerify() {
  if (!currentJWT) return;

  const secret = DOM.verifySecret.value.trim();
  const alg    = DOM.verifyAlg.value;

  if (!secret) {
    showVerifyResult('error', 'Please enter a secret or public key.');
    return;
  }

  DOM.btnVerify.disabled    = true;
  DOM.btnVerify.textContent = 'Verifying…';
  DOM.btnVerify.classList.add('loading');
  hide(DOM.verifyResult);

  try {
    const valid = await verifySignature(
      currentJWT.signingInput,
      currentJWT.signature,
      secret,
      alg
    );

    if (valid) {
      showVerifyResult('valid', '✓ Signature is valid — the token has not been tampered with.');
      DOM.metaSig.textContent = '✓ Valid';
      DOM.metaSig.style.color = 'var(--c-pass)';
    } else {
      showVerifyResult('invalid', '✗ Signature is INVALID — the token may have been tampered with or the wrong key was used.');
      DOM.metaSig.textContent = '✗ Invalid';
      DOM.metaSig.style.color = 'var(--c-critical)';
    }
  } catch (err) {
    showVerifyResult('error', `⚠ Verification error: ${err.message}`);
    DOM.metaSig.textContent = '⚠ Error';
    DOM.metaSig.style.color = 'var(--c-medium)';
  } finally {
    DOM.btnVerify.disabled = false;
    DOM.btnVerify.innerHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M12 2L3 7V13C3 18 7.5 22.5 12 23C16.5 22.5 21 18 21 13V7L12 2Z" stroke="currentColor" stroke-width="2"/>
        <path d="M9 12L11 14L15 10" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      Verify Signature`;
    DOM.btnVerify.classList.remove('loading');
  }
}

function showVerifyResult(type, msg) {
  DOM.verifyResult.className  = `verify-result vr-${type === 'valid' ? 'valid' : type === 'invalid' ? 'invalid' : 'error'}`;
  DOM.verifyResult.textContent = msg;
  show(DOM.verifyResult);
}

function handleAlgChange() {
  updateKeyHint(DOM.verifyAlg.value);
  hide(DOM.verifyResult);
}

function handleClear() {
  DOM.jwtInput.value = '';
  resetUI();
  DOM.jwtInput.focus();
}

function handleSample() {
  DOM.jwtInput.value = generateSampleToken();
  processToken(DOM.jwtInput.value.trim());
  DOM.jwtInput.focus();
}

function handleCopyBtn(e) {
  const btn = e.target.closest('.btn-copy');
  if (!btn) return;
  const targetId = btn.dataset.target;
  const el = document.getElementById(targetId);
  if (!el) return;

  // Extract plain text from syntax-highlighted HTML
  const text = el.innerText || el.textContent;
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = 'Copy';
      btn.classList.remove('copied');
    }, 1800);
  }).catch(() => {
    btn.textContent = 'Failed';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1800);
  });
}


// ══════════════════════════════════════════════════════════════
// 10. INIT
// ══════════════════════════════════════════════════════════════

function init() {
  // Populate DOM cache
  DOM = {
    jwtInput:       document.getElementById('jwt-input'),
    inputStatus:    document.getElementById('input-status'),
    tokenVisual:    document.getElementById('token-visual'),
    metaAlg:        document.getElementById('meta-alg'),
    metaClaims:     document.getElementById('meta-claims'),
    metaSig:        document.getElementById('meta-sig'),
    decodedHeader:  document.getElementById('decoded-header'),
    decodedPayload: document.getElementById('decoded-payload'),
    claimCount:     document.getElementById('claim-count'),
    findings:       document.getElementById('findings'),
    auditTs:        document.getElementById('audit-ts'),
    cntCritical:    document.getElementById('cnt-critical'),
    cntHigh:        document.getElementById('cnt-high'),
    cntMedium:      document.getElementById('cnt-medium'),
    cntPass:        document.getElementById('cnt-pass'),
    scoreCritical:  document.querySelector('.sc-critical'),
    scoreHigh:      document.querySelector('.sc-high'),
    scoreMedium:    document.querySelector('.sc-medium'),
    scorePass:      document.querySelector('.sc-pass'),
    verifyAlg:      document.getElementById('v-alg'),
    verifySecret:   document.getElementById('v-secret'),
    verifyResult:   document.getElementById('verify-result'),
    keyHint:        document.getElementById('key-hint'),
    btnVerify:      document.getElementById('btn-verify'),
    btnSample:      document.getElementById('btn-sample'),
    btnClear:       document.getElementById('btn-clear'),
    emptyState:     document.getElementById('empty-state'),
    cardBreakdown:  document.getElementById('card-breakdown'),
    cardHeader:     document.getElementById('card-header'),
    cardPayload:    document.getElementById('card-payload'),
    cardScore:      document.getElementById('card-score'),
    cardAudit:      document.getElementById('card-audit'),
    cardVerify:     document.getElementById('card-verify'),
  };

  // Attach event listeners
  DOM.jwtInput.addEventListener('input', handleInput);
  DOM.jwtInput.addEventListener('paste', () => setTimeout(handleInput, 0));
  DOM.btnVerify.addEventListener('click', handleVerify);
  DOM.btnSample.addEventListener('click', handleSample);
  DOM.btnClear.addEventListener('click', handleClear);
  DOM.verifyAlg.addEventListener('change', handleAlgChange);

  // Copy buttons use event delegation
  document.addEventListener('click', handleCopyBtn);

  // Allow Ctrl/Cmd+Enter to verify
  DOM.verifySecret.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') handleVerify();
  });

  // Check if a token was passed in the URL hash (share-link friendly)
  const hash = window.location.hash.slice(1);
  if (hash && hash.split('.').length === 3) {
    DOM.jwtInput.value = decodeURIComponent(hash);
    processToken(DOM.jwtInput.value.trim());
  }
}

// Bootstrap
document.addEventListener('DOMContentLoaded', init);
