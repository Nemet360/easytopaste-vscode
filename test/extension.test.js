/**
 * The two things worth testing without a running editor: what the settings
 * clamp to, and that a failure is explained rather than echoed.
 *
 * `vscode` is not a real module outside the editor host, so it is stubbed
 * through a module-resolution hook before the extension is required.
 */
const assert = require('node:assert/strict');
const test = require('node:test');
const Module = require('node:module');

let configValues = {};
const stub = {
  workspace: {
    getConfiguration: () => ({ get: (k, d) => (k in configValues ? configValues[k] : d) }),
  },
  window: {}, commands: {}, env: {}, ProgressLocation: { Notification: 15 },
};
const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === 'vscode') return 'vscode';
  return realResolve.call(this, request, ...rest);
};
require.cache.vscode = { id: 'vscode', filename: 'vscode', loaded: true, exports: stub };

const ext = require('../src/extension.js');

test('expiry is clamped to what the service accepts', () => {
  configValues = { expiryDays: 99 };
  assert.equal(ext.settings('1.0.0').days, 30);
  configValues = { expiryDays: 0 };
  assert.equal(ext.settings('1.0.0').days, 1);
  configValues = { expiryDays: 'nonsense' };
  assert.equal(ext.settings('1.0.0').days, 1, 'a bad setting must not become NaN days');
  configValues = {};
  assert.equal(ext.settings('1.0.0').days, 1);
});

test('one-time is on unless it is explicitly turned off', () => {
  configValues = {};
  assert.equal(ext.settings('1.0.0').oneTime, true);
  configValues = { oneTime: false };
  assert.equal(ext.settings('1.0.0').oneTime, false);
});

test('the quota wall is explained in words a person can act on', () => {
  const text = ext.describe({ code: 'quota_exceeded', message: 'Daily cap hit.' });
  assert.match(text, /per outgoing IP address/);
  assert.match(text, /midnight UTC/);
  assert.match(ext.describe({ code: 'network', message: 'down' }), /could not reach/);
});

test('the share command actually runs: vendor modules load and only ciphertext is sent', async () => {
  // The test that was missing. 0.1.0 shipped with the vendor files unloadable
  // (no "type": "module" beside them) and with api.js importing
  // './vendor/link.js' from inside vendor/ — two fatal defects that three
  // passing tests never touched, because none of them reached modules().
  const posts = [];
  const server = require('node:http').createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      posts.push({ url: req.url, headers: req.headers, body: JSON.parse(body || '{}') });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ locator: 'ZZZZ2345ZZZZ6789', expiresAt: '2026-11-21T00:00:00Z' }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;

  let copied = null;
  const messages = [];
  Object.assign(stub.window, {
    activeTextEditor: {
      document: { getText: () => 'hunter2' },
      selection: {},
    },
    showWarningMessage: (m) => messages.push(m),
    showErrorMessage: (m) => messages.push(m),
    showInformationMessage: (m) => messages.push(m),
    withProgress: (_opts, fn) => fn(),
  });
  stub.env.clipboard = { writeText: async (t) => { copied = t; } };
  configValues = { apiBase: base, appBase: 'https://app.easytopaste.com' };

  const registered = {};
  stub.commands.registerCommand = (id, fn) => { registered[id] = fn; return { dispose() {} }; };
  const subs = [];
  ext.activate({ subscriptions: subs, extension: { packageJSON: { version: '9.9.9' } } });
  try {
    await registered['easytopaste.shareSelection']();
  } finally {
    // In a `finally`, because a failing assertion below must not leave the
    // listener open — node --test then waits on the handle and the run hangs
    // instead of reporting the failure. That happened on the first attempt.
    await new Promise((r) => server.close(r));
  }

  assert.equal(posts.length, 1, `expected one POST, saw ${posts.length}: ${messages.join(' | ')}`);
  assert.match(copied ?? '', /^https:\/\/app\.easytopaste\.com\/s\/ZZZZ2345ZZZZ6789#/);
  assert.deepEqual(Object.keys(posts[0].body).sort(), [
    'ciphertext', 'envelopeVersion', 'expiresInDays', 'mimeHint', 'mode',
    'oneTime', 'requiresRecipientLogin', 'sizeBytes', 'type',
  ], 'the request body gained or lost a field');
  assert.ok(!JSON.stringify(posts[0].body).includes('hunter2'), 'plaintext reached the body');
  assert.ok(!JSON.stringify(posts[0].body).includes(copied.split('#')[1]), 'key reached the body');
  assert.match(posts[0].headers['user-agent'], /^easytopaste-vscode\/9\.9\.9/);
});
