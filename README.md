# 🔒 BrowserGate

**CLI security audit tool for npm dependencies, browser extensions, and install scripts.**

[![npm version](https://img.shields.io/npm/v/browser-gate.svg)](https://npmjs.com/package/browser-gate)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why BrowserGate?

Modern development involves hundreds of npm packages and a growing ecosystem of browser extensions. **You have no free CLI to audit:**
1. Are your npm dependencies known-compromised?
2. What permissions does that browser extension actually have?
3. Are any `postinstall` scripts doing suspicious things?

**BrowserGate closes that gap.**

## 🎯 The LinkedIn Browser Extension Gate — Real-World Use Case

On March 2026, a HN post ([1476 points](https://news.ycombinator.com)) revealed that **LinkedIn's browser extension silently scans and flags competing browser extensions** installed in your browser — without meaningful consent. This surfaced a broader issue: developers and users have no easy way to:

- See what permissions an extension actually requests
- Audit extensions across a team/organization
- Detect extensions that profile other extensions

BrowserGate's `extension-check` command gives developers and security teams a **free, scriptable way to audit extension permissions** directly from the CLI, and the `install-script-scan` catches extensions (or npm packages) using malicious install scripts to exfiltrate data.

## Features

### Commands

#### `browser-gate audit`
Check `node_modules` against a curated list of known-compromised npm packages.

```bash
npx browser-gate audit
browser-gate audit --path ./node_modules --output audit.json
```

#### `browser-gate install-script-scan`
Flag suspicious `postinstall` / `preinstall` scripts that:
- `curl`/`wget` remote content
- Use `eval()` or `exec()`
- Reference credentials/secrets
- Decode base64 payloads
- Check for specific environment variables

```bash
browser-gate install-script-scan
browser-gate install-script-scan --path ./node_modules --output scripts.json
```

#### `browser-gate extension-check <extension-id>`
Analyze a Chrome extension's permissions using the Chrome Web Store API.

```bash
browser-gate extension-check aefhdklifcbnjheakahepceelplnmgkh
browser-gate extension-check aefhdklifcbnjheakahepceelplnmgkh --output extension-report.json
```

> Find an extension ID: Install the extension, go to `chrome://extensions/`, enable Developer Mode, and "Pack extension" — or inspect the Web Store URL.

#### `browser-gate report`
Generate a combined JSON or HTML security report.

```bash
browser-gate report
browser-gate report --format html --output security-report.html
```

## Installation

### From npm (published package)
```bash
npm install -g browser-gate
```

### From source
```bash
git clone https://github.com/dnardelli91/browser-gate.git
cd browser-gate
npm install
npm run build
npm link  # or: node dist/index.js <command>
```

## Quick Start

```bash
# Audit your project's dependencies
browser-gate audit

# Scan install scripts
browser-gate install-script-scan

# Check a browser extension
browser-gate extension-check <EXTENSION_ID>

# Generate full HTML report
browser-gate report --format html --output report.html
```

## Security Notes

- `browser-gate` does **not** collect or transmit any data
- All scans run **locally** on your machine
- The compromised packages list is curated and stored in-source
- Extension data comes from the **public** Chrome Web Store API only

## Roadmap

- [ ] Publish to npm registry
- [ ] Add npm audit API integration (official socket:443 data)
- [ ] Support Firefox add-on permission checks
- [ ] CSV output format
- [ ] Config file (`.browsergaterc`) for custom package allowlists
- [ ] GitHub Actions integration
- [ ] CI/CD gate (fail builds on critical findings)

## Contributing

Issues and PRs welcome! Please see [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT © [dnardelli91](https://github.com/dnardelli91)
