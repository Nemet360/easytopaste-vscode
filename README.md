# EasyToPaste for VS Code

Select the value. Run **EasyToPaste: Share selection as a one-time link**. The
link is on your clipboard.

> **Not on the Marketplace yet.** Publishing needs a Marketplace publisher
> account, which is the owner's to create. Until then this installs from the
> packaged file: `code --install-extension easytopaste-0.1.0.vsix`.

## What it does

Encrypts the selection in the editor with AES-256-GCM and a fresh 32-byte key,
sends **only the ciphertext**, and builds a link whose fragment — the part
after the `#`, which no HTTP client transmits — carries the key. The service
stores a blob it cannot read. The link dies on first read by default.

## What leaves your editor

The ciphertext, its size, the expiry and the one-time flag. Nothing else: not
the selection, not the key, not the file name, the workspace, the language or
anything about what you are working on. No telemetry.

## Settings

| setting | default | meaning |
| --- | --- | --- |
| `easytopaste.expiryDays` | `1` | whole days until the link expires (1–30) |
| `easytopaste.oneTime` | `true` | destroy the secret on first read |
| `easytopaste.apiBase` | *(empty)* | override for a self-hosted deployment |
| `easytopaste.appBase` | *(empty)* | origin used to build links |

## The limit you will meet first

Anonymous callers share a daily allowance of **10 creates per outgoing IP
address** — which an office or a VPN shares across everybody on it. There is
no long-lived API key yet; when the allowance is gone the extension says so in
words rather than failing quietly.

What it is: <https://easytopaste.com/?utm_source=vscode&utm_medium=extension&utm_campaign=launch-2026-11>
· how the encryption works: <https://easytopaste.com/how-it-works/?utm_source=vscode&utm_medium=extension&utm_campaign=launch-2026-11>
· the same thing from a terminal: `npm i -g easytopaste`
