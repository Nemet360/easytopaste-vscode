/**
 * EasyToPaste for VS Code — turn the thing you were about to paste into a
 * one-time link, without leaving the editor.
 *
 * The whole extension is one command. That is on purpose: the moment a
 * developer is about to hand someone a credential is the moment it is already
 * selected in an editor, and anything more than "selection → link on the
 * clipboard" is in the way.
 *
 * CommonJS, because that is still what VS Code loads an extension as, while
 * the crypto and link modules this shares with the CLI are ES modules and must
 * stay byte-identical to them. `await import()` is the bridge, and it is
 * resolved once and cached rather than on every keystroke.
 *
 * What leaves the editor: ciphertext and four small numbers. Never the
 * selection, never the key, never the file name, the workspace, the language
 * or anything else about what you are working on.
 */
const vscode = require('vscode');

let modulesPromise = null;

function modules() {
  if (!modulesPromise) {
    modulesPromise = Promise.all([
      import('./vendor/crypto.js'),
      import('./vendor/link.js'),
      import('./vendor/api.js'),
    ]).then(([crypto, link, api]) => ({ crypto, link, api }));
  }
  return modulesPromise;
}

/** Read the user's settings, falling back to the public service. */
function settings(version) {
  const cfg = vscode.workspace.getConfiguration('easytopaste');
  return {
    days: Math.min(30, Math.max(1, Number(cfg.get('expiryDays', 1)) || 1)),
    oneTime: cfg.get('oneTime', true) !== false,
    apiBase: String(cfg.get('apiBase', '') || '').trim(),
    appBase: String(cfg.get('appBase', '') || '').trim(),
    version,
  };
}

async function shareSelection(version) {
  const { crypto, link, api } = await modules();
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('EasyToPaste: open a file and select the value to share.');
    return;
  }
  const text = editor.document.getText(editor.selection);
  if (!text) {
    vscode.window.showWarningMessage('EasyToPaste: nothing is selected.');
    return;
  }
  const bytes = new TextEncoder().encode(text).length;
  if (bytes > crypto.MAX_INLINE_BYTES) {
    vscode.window.showErrorMessage(
      `EasyToPaste: the selection is ${bytes} bytes and the limit here is ` +
      `${crypto.MAX_INLINE_BYTES}. A file that size belongs in the web app, ` +
      'which uploads it in chunks.',
    );
    return;
  }

  const opts = settings(version);
  const client = new api.ApiClient({
    ...(opts.apiBase ? { baseUrl: opts.apiBase } : {}),
    version,
  });

  const key = crypto.generateKey();
  try {
    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: 'EasyToPaste: encrypting…' },
      async () => {
        const envelope = await crypto.encryptTextToEnvelope(text, key);
        const created = await client.createSecret({
          ciphertextB64: crypto.toBase64Url(envelope),
          sizeBytes: bytes,
          oneTime: opts.oneTime,
          expiresInDays: opts.days,
        });
        const url = link.buildLink({
          locator: created.locator,
          key,
          ...(opts.appBase ? { appBase: opts.appBase } : {}),
        });
        await vscode.env.clipboard.writeText(url);
        const life = opts.oneTime ? 'dies on first read' : `expires in ${opts.days} day(s)`;
        vscode.window.showInformationMessage(
          `EasyToPaste: link copied to the clipboard — it ${life}.`,
        );
      },
    );
  } catch (err) {
    vscode.window.showErrorMessage(`EasyToPaste: ${describe(err)}`);
  } finally {
    // Best effort in a garbage-collected runtime, done anyway: an editor is a
    // long-lived process, so the window in which a key sits in memory here is
    // much longer than in a command that exits.
    crypto.zeroize(key);
  }
}

/** Turn a failure into something a person can act on. */
function describe(err) {
  if (err?.code === 'quota_exceeded') {
    return 'the daily allowance of anonymous secrets for this network is used up. ' +
      'It is counted per outgoing IP address, which an office shares, and it ' +
      'resets at midnight UTC.';
  }
  if (err?.code === 'rate_limited') return 'too many requests — try again in a minute.';
  if (err?.code === 'network') return `could not reach the service (${err.message}).`;
  return err?.message ?? String(err);
}

function activate(context) {
  const version = context.extension?.packageJSON?.version ?? '0.0.0';
  context.subscriptions.push(
    vscode.commands.registerCommand('easytopaste.shareSelection', () => shareSelection(version)),
  );
}

function deactivate() {}

module.exports = { activate, deactivate, describe, settings };
