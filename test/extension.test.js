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
