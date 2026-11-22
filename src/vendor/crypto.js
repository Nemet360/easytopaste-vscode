/**
 * Client-side cryptography for the EasyToPaste clients.
 *
 * This file is the non-browser half of a contract the browser client already
 * implements (frontend/src/app/crypto/crypto.utils.ts and
 * frontend/src/app/components/create-secret/create-secret.component.ts).
 * A secret created here must open in the web app, and a secret created in the
 * web app must open here, so every constant below is a copy of a decision made
 * there — not a new one:
 *
 *   - AES-256-GCM, 96-bit IV, 128-bit tag, no additional authenticated data.
 *   - A fresh 32-byte key per secret, generated locally and never transmitted.
 *   - Inline text envelope byte layout: [iv 12][tag 16][ciphertext N].
 *   - The envelope travels base64url (RFC 4648 §5, no padding).
 *
 * test/compat.test.js re-reads those two frontend files and fails if the
 * numbers drift apart, because a silent drift means every link this CLI prints
 * is undecryptable in a browser and nothing else would notice.
 *
 * **There is no Node-only API in this file, deliberately.** It is vendored
 * byte-identical into every client (`mcp/`, `vscode/`, `action/`, `chrome/`)
 * and `work/ops/tests/test_distribution_channels.py` fails if a copy drifts.
 * The Chrome extension runs it inside a browser service worker, where
 * `node:crypto` cannot be imported and `Buffer` does not exist, so the two
 * Node-isms this file used to carry are gone: WebCrypto is read from the
 * global `crypto` object (a global in browsers, in service workers, and in
 * Node since 18) and base64url is encoded here instead of delegated to
 * `Buffer`. One crypto file across five clients is worth more than the few
 * lines it saves — the envelope layout is this product's interop contract, and
 * a second copy of it is a second place for it to drift.
 */

/** Key size in bytes (AES-256). */
export const KEY_BYTES = 32;
/** IV size in bytes (96-bit GCM nonce). */
export const IV_BYTES = 12;
/** GCM authentication tag size in bytes (128-bit). */
export const TAG_BYTES = 16;
/** Offset of the ciphertext inside the inline envelope. */
export const CIPHERTEXT_OFFSET = IV_BYTES + TAG_BYTES;
/**
 * Largest inline envelope the API accepts (API_SPEC §4.1: 256 KB).
 * Anything larger is a file secret and goes through the presigned-upload path,
 * which these clients deliberately do not implement (see README).
 */
export const MAX_INLINE_BYTES = 256 * 1024;

/** A failed GCM authentication: wrong key, or tampered ciphertext. */
export class DecryptionError extends Error {
  constructor(message = 'decryption failed — wrong key, or the data was altered') {
    super(message);
    this.name = 'DecryptionError';
  }
}

/** Malformed base64url, envelope or key material. */
export class EnvelopeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'EnvelopeError';
  }
}

/**
 * The host's WebCrypto, resolved lazily and loudly.
 *
 * Not resolved at module load: a module that throws while loading takes the
 * whole client down with a stack trace nobody can act on. A missing `crypto`
 * global means Node older than 18, or a page served from an insecure origin,
 * and both deserve a sentence that says which.
 *
 * @returns {Crypto}
 */
function webcrypto() {
  const host = globalThis.crypto;
  if (!host || !host.subtle || typeof host.getRandomValues !== 'function') {
    throw new EnvelopeError(
      'this runtime has no WebCrypto (globalThis.crypto.subtle). ' +
        'Node 18+ provides it; a browser provides it only on a secure origin.',
    );
  }
  return host;
}

/** @returns {SubtleCrypto} */
function subtleCrypto() {
  return webcrypto().subtle;
}

/**
 * Fill a typed array with cryptographically strong random bytes.
 *
 * Called as a method on the Crypto object rather than detached: WebCrypto's
 * `getRandomValues` checks its receiver and throws when it is not — Node
 * raises ERR_INVALID_THIS, a browser raises an illegal-invocation TypeError.
 *
 * @template {Uint8Array} T
 * @param {T} buf
 * @returns {T}
 */
function fillRandom(buf) {
  const host = webcrypto();
  return host.getRandomValues(buf);
}

/** The base64url alphabet (RFC 4648 §5), used for output. */
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Reverse lookup for decoding, built once.
 *
 * URL-safe alphabet only, with no entry for `+` or `/`. That is not a second
 * guard bolted onto the regex below — the two must agree, and the regex is the
 * one that produces the error message, so a standard-base64 string is refused
 * there with "is not valid base64url" before this table is ever consulted.
 * Adding `+`/`/` here would be code that can never run, which is worse than
 * strictness: it reads as support the client does not have.
 */
const B64URL_INDEX = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64URL.length; i += 1) table[B64URL.charCodeAt(i)] = i;
  return table;
})();

/** @returns {Uint8Array} 32 cryptographically random bytes. */
export function generateKey() {
  return fillRandom(new Uint8Array(KEY_BYTES));
}

/**
 * base64url-encode bytes, unpadded — the alphabet the URL fragment and the
 * API both expect.
 *
 * Written out rather than delegated, because `Buffer` does not exist in a
 * browser service worker and `btoa` takes a string, which would mean building
 * a 256 KB intermediate string out of the very bytes we are trying not to
 * copy around.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toBase64Url(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new EnvelopeError('toBase64Url expects bytes');
  }
  const parts = [];
  let chunk = '';
  let i = 0;
  // Three bytes in, four characters out.
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    chunk +=
      B64URL[(n >>> 18) & 63] + B64URL[(n >>> 12) & 63] + B64URL[(n >>> 6) & 63] + B64URL[n & 63];
    // Flushed in blocks: appending to one string for a 256 KB envelope is
    // ~350k concatenations, and V8's rope representation makes the final read
    // the expensive part rather than the appends.
    if (chunk.length >= 4096) {
      parts.push(chunk);
      chunk = '';
    }
  }
  // The tail, emitted unpadded.
  const left = bytes.length - i;
  if (left === 1) {
    const n = bytes[i] << 16;
    chunk += B64URL[(n >>> 18) & 63] + B64URL[(n >>> 12) & 63];
  } else if (left === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    chunk += B64URL[(n >>> 18) & 63] + B64URL[(n >>> 12) & 63] + B64URL[(n >>> 6) & 63];
  }
  parts.push(chunk);
  return parts.join('');
}

/**
 * Decode unpadded base64url back to bytes, strictly.
 *
 * A lenient decoder — which is what `Buffer.from(value, 'base64url')` is, and
 * what this used to delegate to — silently skips characters outside the
 * alphabet, so a truncated or corrupted fragment decodes to plausible garbage
 * and surfaces later as a confusing GCM failure. The shape is checked first
 * and rejected loudly instead, and the loop below reads every character it was
 * given rather than skipping any.
 *
 * @param {string} value
 * @param {string} what Label used in the error message.
 * @returns {Uint8Array}
 */
export function fromBase64Url(value, what = 'value') {
  if (typeof value !== 'string' || value.length === 0) {
    throw new EnvelopeError(`${what} is empty`);
  }
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(value)) {
    throw new EnvelopeError(`${what} is not valid base64url`);
  }
  const body = value.replace(/=+$/, '');
  // A base64 quantum is four characters. A remainder of one cannot be produced
  // by any encoder, so it means the string lost characters on the way here.
  if (body.length % 4 === 1) {
    throw new EnvelopeError(`${what} is truncated base64url`);
  }
  const out = new Uint8Array(Math.floor((body.length * 3) / 4));
  let written = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < body.length; i += 1) {
    const code = body.charCodeAt(i);
    const digit = code < 128 ? B64URL_INDEX[code] : -1;
    if (digit < 0) {
      throw new EnvelopeError(`${what} is not valid base64url`);
    }
    acc = ((acc << 6) | digit) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[written] = (acc >>> bits) & 0xff;
      written += 1;
    }
  }
  return out.subarray(0, written);
}

/**
 * Encrypt UTF-8 text and pack it into the inline envelope the API stores.
 *
 * @param {string} plaintext
 * @param {Uint8Array} key 32 bytes.
 * @returns {Promise<Uint8Array>} [iv 12][tag 16][ciphertext N]
 */
export async function encryptTextToEnvelope(plaintext, key) {
  assertKey(key);
  const iv = fillRandom(new Uint8Array(IV_BYTES));
  const cryptoKey = await subtleCrypto().importKey(
    'raw',
    key,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const raw = new Uint8Array(
    await subtleCrypto().encrypt(
      { name: 'AES-GCM', iv, tagLength: TAG_BYTES * 8 },
      cryptoKey,
      new TextEncoder().encode(plaintext),
    ),
  );

  // WebCrypto appends the tag to the ciphertext; the envelope carries it in
  // front, exactly as the browser client packs it.
  const ciphertext = raw.subarray(0, raw.length - TAG_BYTES);
  const tag = raw.subarray(raw.length - TAG_BYTES);

  const envelope = new Uint8Array(CIPHERTEXT_OFFSET + ciphertext.length);
  envelope.set(iv, 0);
  envelope.set(tag, IV_BYTES);
  envelope.set(ciphertext, CIPHERTEXT_OFFSET);
  return envelope;
}

/**
 * Unpack an inline envelope and decrypt it back to UTF-8 text.
 *
 * @param {Uint8Array} envelope [iv 12][tag 16][ciphertext N]
 * @param {Uint8Array} key 32 bytes.
 * @returns {Promise<string>}
 */
export async function decryptEnvelopeToText(envelope, key) {
  assertKey(key);
  if (!(envelope instanceof Uint8Array) || envelope.length < CIPHERTEXT_OFFSET) {
    throw new EnvelopeError(
      `envelope is too short: ${envelope?.length ?? 0} bytes, minimum ${CIPHERTEXT_OFFSET}`,
    );
  }
  const iv = envelope.subarray(0, IV_BYTES);
  const tag = envelope.subarray(IV_BYTES, CIPHERTEXT_OFFSET);
  const ciphertext = envelope.subarray(CIPHERTEXT_OFFSET);

  const combined = new Uint8Array(ciphertext.length + TAG_BYTES);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  const cryptoKey = await subtleCrypto().importKey(
    'raw',
    key,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  let plaintext;
  try {
    plaintext = await subtleCrypto().decrypt(
      { name: 'AES-GCM', iv, tagLength: TAG_BYTES * 8 },
      cryptoKey,
      combined,
    );
  } catch {
    // No byte-level detail, for the same reason the web client gives none.
    throw new DecryptionError();
  }
  // Strict, for the same reason the input side is strict: a lenient decoder
  // turns bytes it cannot read into U+FFFD, and `--raw` promises the caller
  // the exact bytes that were encrypted. A text secret created by this CLI or
  // by the browser is always valid UTF-8; anything else did not come from
  // either, and silently replacing bytes would be the worst possible answer.
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
  } catch {
    throw new EnvelopeError(
      'the secret decrypted correctly but is not UTF-8 text, so the client will not print it',
    );
  }
}

/**
 * Overwrite key material in place. A garbage-collected runtime cannot promise
 * the bytes were never copied, so this shortens the window rather than
 * closing it.
 * @param {Uint8Array} bytes
 */
export function zeroize(bytes) {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

function assertKey(key) {
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) {
    throw new EnvelopeError(`key must be ${KEY_BYTES} bytes, got ${key?.length ?? 'none'}`);
  }
}
