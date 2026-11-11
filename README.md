# csix-phish

![csix-phish banner](assets/banner.png)

**Offline phishing URL checker — transparent heuristics, no network, pure Go.**

[![CI](https://github.com/siedysoes/csix-phish/actions/workflows/ci.yml/badge.svg)](https://github.com/siedysoes/csix-phish/actions/workflows/ci.yml)
[![Release](https://github.com/siedysoes/csix-phish/actions/workflows/release.yml/badge.svg)](https://github.com/siedysoes/csix-phish/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`csix-phish` scores the risk of a URL based on explainable heuristics:
brand typosquatting, deceptive subdomains, risky TLDs, URL shorteners,
raw-IP hosts, and dozens of other signals — then gives a **0–100 score**
along with **the reason for every finding** (no black box).

> **100% offline** — URLs are never sent to any server.

## Features

- 🎯 **Score 0–100** + level: `LOW` / `SUSPICIOUS` / `DANGEROUS` / `CRITICAL`
- 🔎 **20+ heuristic signals** with auditable weights
- 🏷️ **Brand typosquatting detection** (paypa1, g00gle, secure-paypal-login...)
  including Indonesian brands (BCA, Gojek, Tokopedia, Shopee, OVO, Dana...)
- 🖥️ **100% client-side web demo** — runs directly on GitHub Pages, no server
- 📦 `--json` for tooling integration
- ⚡ Single binary, zero dependencies, no network access

## Installation

### Prebuilt binaries

Download the latest binary for your platform from the
[Releases page](https://github.com/siedysoes/csix-phish/releases/latest)
(Windows / Linux / macOS, amd64 + arm64), then verify it:

```sh
sha256sum -c checksums.txt
```

### Go

```sh
go install github.com/siedysoes/csix-phish@latest
```

## Usage

```sh
csix-phish http://paypa1-secure.com/login
csix-phish --json https://bit.ly/3xYzAb https://google.com
```

Example output:

```
▸ http://paypa1-secure.com/login
  Host     paypa1-secure.com
  Score    48/100  █████████░░░░░░░░░░░  DANGEROUS

  Risk signals:
   • [ 5] Scheme is not HTTPS — traffic is unencrypted
   • [ 8] Suspicious keywords: login
   • [35] Domain contains brand "paypal"
```

## Options

| Flag | Description |
|------|-------------|
| `--json` | JSON output |
| `--threshold <n>` | Minimum score considered dangerous (default 40 → exit 1) |
| `--no-color` | Disable colored output (also honors `NO_COLOR`) |
| `--version` | Print version |

**Exit codes:** `0` safe · `1` dangerous URL found · `2` error

## Web Demo

The static page in the [`docs/`](docs/) folder uses the same heuristics
(a JavaScript port) and runs entirely in your browser:
**https://siedysoes.github.io/csix-phish/**

## How It Works (transparent)

Every signal has a fixed weight; the total is clamped to 100:

| Signal | Weight |
|--------|-------|
| Brand typosquat (paypa1, g00gle) | 40 |
| Brand in subdomain (paypal.com.evil.net) | 35 |
| Raw IP host | 35 |
| Credentials in URL (user:pass@) | 30 |
| Punycode / decimal number host | 30 |
| Suspicious keywords (max 24) | 8/cluster |
| URL shortener | 20 |
| Risky TLD (.zip, .tk, .xyz...) | 15 |
| etc. — see [`internal/phish/phish.go`](internal/phish/phish.go) | |

**Levels:** `LOW` 0–14 · `SUSPICIOUS` 15–39 · `DANGEROUS` 40–69 · `CRITICAL` 70+

Heuristics are indications, not a final verdict. Always verify manually.

## Languages

- English (this file)
- [Bahasa Indonesia](README.id.md)

## License

MIT — see [LICENSE](LICENSE). For defensive purposes.
