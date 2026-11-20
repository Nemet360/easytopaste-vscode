/**
 * The HTTP half of the extension: one call against the public secrets API.
 *
 * Adapted from the CLI's `src/api.js`, and the differences are deliberate and
 * small — the User-Agent prefix, and `retrieveStatus`, which throws away the
 * envelope the API returns. `vendor/crypto.js` and `vendor/link.js` are
 * byte-identical copies of the CLI's, so a link made by an agent opens in the
 * browser and in the terminal.
 *
 * What this module is allowed to send matters as much as what it does send.
 * It posts ciphertext and metadata, and nothing else: no plaintext, no key, no
 * conversation, no model name, no telemetry. An MCP server sits inside an
 * agent's context, which is the most tempting place in this product to leak
 * something by accident, so the request body is asserted field-by-field in
 * test/api.test.js rather than trusted.
 */

import { DEFAULT_API_BASE } from './vendor/link.js';

const USER_AGENT_PREFIX = 'easytopaste-vscode';

/**
 * Which host installed this server, if the installer said so.
 *
 * Same reasoning as the CLI's: a `utm` tag measures a click on a link, and an
 * agent that creates a secret never loads a page. The MCP directories set
 * EASYTOPASTE_CHANNEL so a Smithery install is distinguishable from a manual
 * one. Sanitised rather than trusted: the value comes from the environment and
 * goes into a header, where a stray newline is a request-splitting bug.
 */
export function channelTag(env = process.env) {
  const raw = String(env.EASYTOPASTE_CHANNEL ?? '').trim().toLowerCase();
  return raw.replace(/[^a-z0-9-]/g, '').slice(0, 16);
}

/** `easytopaste-vscode/0.1.0` or `easytopaste-vscode/0.1.0 (marketplace)`. */
export function userAgent(version, env = process.env) {
  const channel = channelTag(env);
  return channel
    ? `${USER_AGENT_PREFIX}/${version} (${channel})`
    : `${USER_AGENT_PREFIX}/${version}`;
}

export class ApiError extends Error {
  constructor(message, info = {}) {
    super(message);
    this.name = 'ApiError';
    this.code = info.code ?? 'unknown';
    this.status = info.status ?? 0;
    this.requestId = info.requestId ?? null;
    this.retryAfter = info.retryAfter ?? null;
  }
}

export class NetworkError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'NetworkError';
    this.code = 'network';
    this.cause = cause;
  }
}

export class ApiClient {
  constructor({
    baseUrl = DEFAULT_API_BASE,
    version = '0.0.0',
    token = '',
    timeoutMs = 15000,
    fetchImpl = globalThis.fetch,
    env = process.env,
  } = {}) {
    this.baseUrl = String(baseUrl).replace(/\/+$/, '');
    this.version = version;
    this.token = token;
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
    this.env = env;
  }

  /** POST /v1/secrets — the create body, identical in shape to the CLI's. */
  async createSecret({ ciphertextB64, sizeBytes, oneTime, expiresInDays }) {
    const body = {
      type: 'text',
      mode: 'link',
      envelopeVersion: 1,
      sizeBytes,
      oneTime,
      expiresInDays,
      requiresRecipientLogin: false,
      mimeHint: 'text/plain',
      ciphertext: ciphertextB64,
    };
    const json = await this.#request('POST', '/v1/secrets', body);
    if (!json || typeof json.locator !== 'string') {
      throw new ApiError('the API accepted the secret but returned no locator');
    }
    return json;
  }

  /**
   * GET /v1/secrets/{locator}, reduced to status.
   *
   * The endpoint returns the envelope alongside the metadata. An agent asking
   * "is it still there" must not receive ciphertext it did not ask for and
   * cannot read — it would end up in a transcript, which is the exact place
   * this product exists to keep secrets out of. So the envelope is dropped
   * here, in the one function that sees it, rather than filtered later.
   *
   * It does NOT burn: that is POST /burn, which this server does not call.
   */
  async retrieveStatus(locator) {
    const json = await this.#request(
      'GET', `/v1/secrets/${encodeURIComponent(locator)}`,
    ) ?? {};
    return {
      locator: json.locator ?? locator,
      status: json.status ?? 'unknown',
      oneTime: json.oneTime ?? null,
      expiresAt: json.expiresAt ?? null,
      sizeBytes: json.sizeBytes ?? null,
      createdAt: json.createdAt ?? null,
    };
  }

  async #request(method, path, body) {
    const headers = {
      accept: 'application/json',
      'user-agent': userAgent(this.version, this.env),
    };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (this.token) headers.authorization = `Bearer ${this.token}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (cause) {
      throw new NetworkError(`could not reach ${this.baseUrl}: ${cause?.message ?? cause}`, cause);
    } finally {
      clearTimeout(timer);
    }

    let json = null;
    try {
      json = await response.json();
    } catch {
      json = null;
    }

    if (!response.ok) {
      const err = json?.error ?? {};
      throw new ApiError(err.message || `the API answered ${response.status}`, {
        code: err.code,
        status: response.status,
        requestId: err.request_id ?? err.requestId,
        retryAfter: response.headers?.get?.('retry-after') ?? null,
      });
    }
    return json;
  }
}
