/**
 * Client-side cryptography for the EasyToPaste CLI.
 *
 * This file is the terminal half of a contract the browser client already
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
 */

import { webcrypto } from 'node:crypto';

const { subtle } = webcrypto;
// Bound, not destructured: webcrypto.getRandomValues checks its receiver and
// throws ERR_INVALID_THIS when it is called detached from the Crypto object.
const getRandomValues = webcrypto.getRandomValues.bind(webcrypto);

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
 * which this CLI deliberately does not implement (see README).
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

/** @returns {Uint8Array} 32 cryptographically random bytes. */
export function generateKey() {
  return getRandomValues(new Uint8Array(KEY_BYTES));
}

/**
 * base64url-encode bytes, unpadded — the alphabet the URL fragment and the
 * API both expect.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

/**
 * Decode unpadded base64url back to bytes, strictly.
 *
 * Buffer's own base64url decoder silently skips characters outside the
 * alphabet, so a truncated or corrupted fragment would decode to plausible
 * garbage and surface later as a confusing GCM failure. The shape is checked
 * first and rejected loudly instead.
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
  return new Uint8Array(Buffer.from(value, 'base64url'));
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
  const iv = getRandomValues(new Uint8Array(IV_BYTES));
  const cryptoKey = await subtle.importKey('raw', key, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
  ]);
  const raw = new Uint8Array(
    await subtle.encrypt(
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

  const cryptoKey = await subtle.importKey('raw', key, { name: 'AES-GCM', length: 256 }, false, [
    'decrypt',
  ]);
  let plaintext;
  try {
    plaintext = await subtle.decrypt(
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
      'the secret decrypted correctly but is not UTF-8 text, so the CLI will not print it',
    );
  }
}

/**
 * Overwrite key material in place. Node cannot promise the bytes were never
 * copied by the GC, so this shortens the window rather than closing it.
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
