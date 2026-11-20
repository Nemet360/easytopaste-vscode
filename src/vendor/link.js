/**
 * Share-link construction and parsing.
 *
 * The link shape is the browser client's (result-screen.component.ts):
 *
 *     https://app.easytopaste.com/s/<locator>#k=<base64url key>&v=1
 *
 * Everything after `#` is a URL fragment, which browsers and HTTP clients do
 * not transmit — that is the whole reason the key lives there. This module
 * never logs or forwards the fragment; it only moves it between the link and
 * the local crypto calls.
 */

import { EnvelopeError, KEY_BYTES, fromBase64Url, toBase64Url } from './crypto.js';

export const DEFAULT_APP_BASE = 'https://app.easytopaste.com';
export const DEFAULT_API_BASE = 'https://api.easytopaste.com';

/** Locators are base32 (A-Z2-7); the wider class is what we will *accept*. */
const LOCATOR_RE = /^[A-Za-z0-9_-]{8,128}$/;

export class LinkError extends Error {
  constructor(message) {
    super(message);
    this.name = 'LinkError';
  }
}

/**
 * @param {{locator: string, key: Uint8Array, appBase?: string}} args
 * @returns {string} The full one-time link, fragment included.
 */
export function buildLink({ locator, key, appBase = DEFAULT_APP_BASE }) {
  assertLocator(locator);
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) {
    throw new LinkError(`key must be ${KEY_BYTES} bytes`);
  }
  const base = String(appBase).replace(/\/+$/, '');
  return `${base}/s/${locator}#k=${toBase64Url(key)}&v=1`;
}

/**
 * Parse a share link back into its locator and key.
 *
 * Accepts the full URL, or the short `<locator>#k=<key>` form that is easier
 * to paste between terminals.
 *
 * @param {string} input
 * @returns {{locator: string, key: Uint8Array}}
 */
export function parseLink(input) {
  if (typeof input !== 'string' || input.trim() === '') {
    throw new LinkError('no link given');
  }
  const raw = input.trim();
  const hashAt = raw.indexOf('#');
  if (hashAt === -1) {
    throw new LinkError(
      'that link carries no "#k=" fragment, so it holds no key. ' +
        'Copy the whole link, including everything after the "#".',
    );
  }

  const before = raw.slice(0, hashAt);
  const fragment = raw.slice(hashAt + 1);

  const params = new URLSearchParams(fragment);
  const keyPart = params.get('k');
  if (!keyPart) {
    throw new LinkError('the link fragment has no "k=" key parameter');
  }
  const version = params.get('v');
  if (version !== null && version !== '1') {
    throw new LinkError(
      `link envelope version ${version} is newer than this CLI understands (expected 1)`,
    );
  }

  let key;
  try {
    key = fromBase64Url(keyPart, 'key fragment');
  } catch (err) {
    throw new LinkError(err.message);
  }
  if (key.length !== KEY_BYTES) {
    throw new LinkError(
      `key fragment decodes to ${key.length} bytes, expected ${KEY_BYTES} — the link is truncated`,
    );
  }

  const locator = extractLocator(before);
  return { locator, key };
}

function extractLocator(before) {
  // A link that travelled through Slack or an email client arrives with a
  // tracking query attached: /s/<locator>?utm_source=slack#k=... The browser
  // opens that fine, so refusing it here would be the CLI inventing a rule the
  // product does not have. The query is not part of the locator and is dropped.
  const trimmed = before.split('?')[0].replace(/\/+$/, '');
  if (trimmed === '') {
    throw new LinkError('the link has no locator before the "#"');
  }
  // Full URL form: .../s/<locator>. Bare form: <locator>.
  const segments = trimmed.split('/');
  const candidate = segments[segments.length - 1];
  assertLocator(candidate);
  return candidate;
}

function assertLocator(locator) {
  if (typeof locator !== 'string' || !LOCATOR_RE.test(locator)) {
    throw new LinkError(`"${locator}" is not a valid secret locator`);
  }
}
