<div align="center">

# RevENG — Reverse Engineering Platform

**A cross-platform toolkit for binary analysis, decompilation, and security research.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)
![UI](https://img.shields.io/badge/UI-PyQt6-41CD52.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

[Features](#features) · [Install](#installation) · [Usage](#usage) · [Optional integrations](#optional-integrations) · [Configuration](#configuration) · [Contributing](#contributing)

</div>

---

RevENG is an all-in-one desktop workbench for understanding binaries — Windows, Linux,
and macOS — combining classic static analysis (disassembly, control-flow graphs,
entropy, security auditing) with AI-assisted decompilation and live, decrypted API
capture. It's built for security researchers, students, and CTF players who want a
deep, navigable map of what a program does, all behind a single PyQt6 interface.

> **Scope, honestly:** like every RE tool (IDA, Ghidra, Binary Ninja), RevENG recovers a
> faithful *structural* understanding — disassembly, control flow, and decompiled C — but
> **not** the original source with its real names and comments, and it does not
> automatically defeat strong obfuscation, packing, or DRM. It maps what software does;
> it does not reprint its source.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Option A — Download a pre-built app](#option-a--download-a-pre-built-app-recommended-for-end-users)
  - [Option B — One-command install from source](#option-b--one-command-install-from-source)
  - [Option C — Manual setup (developers)](#option-c--manual-setup-developers)
- [Building standalone apps](#building-standalone-apps)
- [Usage](#usage)
- [Optional integrations](#optional-integrations)
- [Configuration](#configuration)
- [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)
- [Roadmap & docs](#roadmap--docs)
- [Contributing](#contributing)
- [Legal & ethical use](#legal--ethical-use)
- [License](#license)

---

## Features

- **AI decompilation** — turns assembly into readable C-like code using a local LLM
  (via [Ollama](https://ollama.com)); results appear in the **Source Code** tab. No
  code leaves your machine.
- **Live API capture (decrypted)** — launch a target app or CLI tool through a local
  HTTPS interceptor and get a structured, real-time view of every API call: method +
  URL, request/response headers and bodies, and extracted **API keys, Bearer tokens,
  JWTs, and secrets**. No system-wide proxy or certificate needed for apps RevENG
  launches (Electron, Node, Python, curl). *Cert-pinned native apps require Frida
  hooking — on the [roadmap](ROADMAP.md).*
- **Whole-application analysis** — point the **Full Software** tab at a folder, `.app`
  bundle, installer, or archive (`.apk` / `.ipa` / `.jar` / `.zip`). It **recurses into
  nested archives** (shown as `app.apk!/lib.jar!/…`), classifies every file, and
  produces an application-wide summary plus per-file deep dives.
- **Packer / protector detection** — recognizes UPX, ASPack, VMProtect, Themida, Enigma,
  MPRESS, and more. **UPX is unpacked automatically**; for heavy commercial protectors,
  RevENG tells you honestly rather than pretending to break them.
- **Security audit** — scans for hardcoded secrets, weak crypto, and other issues,
  grouped by type with remediation guidance.
- **Key / token extraction** — locates cryptographic keys and tokens and attempts to
  crack them.
- **Modern GUI** — a 19-tab PyQt6 workbench with a real-time analysis log, so nothing
  ever fails silently.

---

## Installation

RevENG runs on **macOS, Linux, and Windows**, and is tested on **Python 3.11 and 3.12**.
There are three ways to install, depending on who you are.

### Option A — Download a pre-built app (recommended for end users)

No Python setup required. Grab the latest build for your platform from the
[**Releases**](../../releases) page, unpack it, and launch:

| Platform | File | Launch |
|---|---|---|
| **macOS** | `RevENG-macos.zip` | Open `RevENG.app` *(first run: right-click → Open to bypass Gatekeeper)* |
| **Windows** | `RevENG-windows.zip` | Run `RevENG\RevENG.exe` |
| **Linux** | `RevENG-linux.tar.gz` | Run `RevENG/RevENG` |

Your settings, projects, and plugins live in your user data folder
(`~/Library/Application Support/RevENG` on macOS, `%APPDATA%\RevENG` on Windows,
`~/.config/RevENG` on Linux).

### Option B — One-command install from source

If you cloned the repo or downloaded the source, this creates an isolated `.venv`,
installs the core dependencies (including the 3D CFG WebEngine viewer), and drops a
launcher script:

```bash
# macOS / Linux
./scripts/install.sh
./RevENG

# Windows
scripts\install.bat
RevENG.bat
```

Heavy optional tools (Ghidra, Ollama, mitmproxy, Frida) are installed separately —
see [Optional integrations](#optional-integrations).

### Option C — Manual setup (developers)

```bash
# 1. Create an isolated environment
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate

# 2. Install core dependencies
pip install -r requirements.txt

# 3. Run the app
python main.py
```

---

## Building standalone apps

RevENG ships a [PyInstaller](https://pyinstaller.org) spec that produces a
self-contained app requiring no Python on the target machine. **PyInstaller does not
cross-compile — each platform's build must run on that platform.**

**Locally (builds for the current OS only):**

```bash
# macOS / Linux
./scripts/build_release.sh

# Windows
scripts\build_release.bat
```

Output: `dist/RevENG.app` (macOS), `dist/RevENG/RevENG` (Linux), or
`dist/RevENG/RevENG.exe` (Windows).

**All three platforms at once (CI):** the [`Release`](.github/workflows/release.yml)
GitHub Actions workflow builds macOS, Linux, and Windows on native runners in parallel.

- **Publish a release** — push a version tag; the workflow builds all three and attaches
  them to a GitHub Release:
  ```bash
  git tag v1.0.0 && git push origin v1.0.0
  ```
- **Build artifacts only** — trigger the workflow manually from the **Actions** tab
  (**Run workflow**); it produces the three per-OS archives without creating a Release.

---

## Usage

On launch you'll see a **Welcome screen** with two modes:

- **Cracking** — the general reverse-engineering workbench.
- **Security** — opens straight to the Security Audit tab.

Both open the same 19-tab workbench. From there:

- **Single binary** (`.exe`, `.dll`, `.so`, `.dylib`, any Mach-O/ELF/PE) — use
  **File → Open Binary** for disassembly, a navigable function list, control-flow
  graphs, entropy/sections, security audit, strings/keys, and decompiled C (when a
  decompiler backend is installed).
- **Whole application** (a folder or archive) — use the **Full Software** tab and point
  it at the target; it recurses into archives and produces an application-wide report.

The **Analysis Log** tab prints a capability report on startup, so you always know which
optional backends are active.

---

## Optional integrations

The core workflow runs with just `requirements.txt`. Enhanced features are
**auto-detected at startup** — their buttons are disabled with an explanatory tooltip
when a backend is missing. Install the extras you want:

```bash
pip install -r requirements-optional.txt
```

| Feature | Requires | How to enable |
|---|---|---|
| AI decompilation / summaries / Q&A | **Ollama** | `ollama serve` + `ollama pull llama3.2` |
| Ghidra decompilation | **Ghidra** | add `analyzeHeadless` to `PATH` or set `GHIDRA_HEADLESS` |
| RetDec decompilation | **RetDec** | add `retdec-decompiler` to `PATH` |
| Network / API capture | **mitmproxy** | `pip install mitmproxy` (provides `mitmdump`) |
| Kernel TLS capture *(Linux)* | **bcc** + root | `pip install -r requirements-optional-linux.txt` |
| Symbolic execution / emulation | angr / unicorn | included in `requirements-optional.txt` |
| Dynamic instrumentation | Frida | included in `requirements-optional.txt` |

> **Linux note:** the bundled 3D CFG viewer uses Qt WebEngine. If it fails to render on a
> minimal system, install the runtime libraries (Debian/Ubuntu):
> `sudo apt-get install libnss3 libegl1 libgl1 libxkbcommon0 libdbus-1-3`.

---

## Configuration

**Environment variables** (see [`.env.example`](.env.example)):

| Variable | Purpose | Default |
|---|---|---|
| `OPENAI_API_KEY` | Optional cloud AI provider | *(unset)* |
| `OLLAMA_HOST` | Local Ollama host | `localhost` |
| `OLLAMA_PORT` | Local Ollama port | `11434` |
| `REVENG_DATA_DIR` | Override the user data directory | platform default |
| `GHIDRA_HEADLESS` | Path to Ghidra `analyzeHeadless` | *(unset)* |

**App settings** are stored in [`config.json`](config.json) (theme, fonts, disassembly
options, AI model, etc.) and can be edited from the in-app Settings dialog.

---

## Project layout

```
main.py               # Entry point
src/
  gui/                # PyQt6 UI (tabs, theming, welcome screen)
  core/               # Analysis engines, loaders, decompilers
  intelligence/       # Threat intel and IOC extraction
  plugins/            # Plugin manager and extension points
  utils/              # Paths, settings, logging
packaging/            # PyInstaller spec
scripts/              # install / build / analysis helper scripts
plugins/              # Bundled plugins
docs/                 # Architecture and full user guide
```

---

## Troubleshooting

- **Missing-dependency errors** — confirm your virtualenv is active and re-run
  `pip install -r requirements.txt`.
- **AI features disabled** — Ollama must be running locally (`ollama serve`) and a model
  pulled (`ollama pull llama3.2`).
- **Network capture not working** — ensure `mitmproxy` is installed and `mitmdump` is on
  your `PATH`.
- **Anything else** — check the **Analysis Log** tab in the app; it usually explains the
  problem in plain language.

---

## Roadmap & docs

- [Full user guide](docs/REVENG_COMPLETE_GUIDE.md)
- [Target architecture](docs/ARCHITECTURE_TARGET.md)
- [Roadmap](ROADMAP.md) · [Changelog](CHANGELOG.md)

---

## Contributing

Contributions are welcome! To get started:

1. Fork the repo and create a feature branch.
2. Set up the dev environment: `pip install -r requirements.txt -r requirements-dev.txt`.
3. Run the checks before opening a PR:
   ```bash
   ruff check src tests
   pytest
   ```
4. Open a pull request describing the change. For larger features, open an
   [issue](../../issues) first to discuss the approach.

CI runs linting and the test suite on Linux and macOS across Python 3.11 and 3.12.

---

## Legal & ethical use

RevENG is intended for **authorized security research, education, CTF competitions, and
analysis of software you own or have explicit permission to inspect.** Reverse
engineering may be restricted by law, license agreements, or terms of service in your
jurisdiction. You are solely responsible for ensuring your use is lawful. The authors
accept no liability for misuse.

---

## License

Released under the [MIT License](LICENSE).
