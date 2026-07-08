# 👋 Welcome to the Ultimate Reverse Engineering Platform

**Your Swiss Army Knife for Binary Analysis, Decompilation, and Security Research**

---

## What is this?
This platform is a friendly, all-in-one toolkit for anyone interested in reverse engineering, binary analysis, and software security. Whether you're a security pro, a student, or just curious, this tool helps you dig deep into binaries—Windows, Linux, or macOS—using both classic and AI-powered techniques.

---

## Why You'll Love It
- **AI Decompilation:**
  - Converts tricky assembly into readable C-like code using local LLMs (like Ollama).
  - See results instantly in the "Source Code" tab!
- **Live API Capture (decrypted):**
  - Point it at the loaded app (or any binary/CLI tool) and hit *Capture & Launch* —
    the tool launches that app through a local HTTPS interceptor with the mitmproxy
    CA trusted via env vars, so its **HTTPS is decrypted**.
  - Structured, real-time view of every **API call**: method + URL, request/response
    headers and bodies, and extracted **API keys / Bearer tokens / JWTs / secrets** —
    not a Wireshark packet dump.
  - No system-wide proxy/cert needed for apps the tool launches (Electron, Node,
    Python, curl/CLI). Native apps that pin certificates won't decrypt this way
    (that needs Frida hooking — on the roadmap). Requires `pip install mitmproxy`.
- **Security Audit:**
  - Scans for hardcoded secrets, weak crypto, and more.
  - Groups findings by type and tells you how to patch them.
- **Key/Token Extraction:**
  - Finds and tries to crack cryptographic keys and tokens.
- **Modern, Friendly GUI:**
  - PyQt6 interface with tabs for everything you need.
  - Real-time log view so you're never in the dark.

---

## Quickstart
Works on macOS, Linux, and Windows. Python 3.11 / 3.12 are the primary targets
(3.13/3.14 also work with current wheels).

```bash
# 1. Create an isolated environment
python3 -m venv .venv

# 2. Install the core dependencies (everything needed for the core workflow)
.venv/bin/pip install -r requirements.txt          # Windows: .venv\Scripts\pip

# 3. Run the app
.venv/bin/python main.py                            # Windows: .venv\Scripts\python
```

On launch you'll get a **Welcome screen** with two modes — **Cracking** (general
RE workbench) and **Security** (opens straight on the Security Audit tab). Both
open the same **19-tab workbench**; pick either, then **File → Open Binary**.

### Optional power features
The app runs fully without these. Each is **auto-detected at startup** and its
button is disabled with a tooltip if the backend isn't installed (so nothing ever
fails silently). Install what you need:

```bash
.venv/bin/pip install -r requirements-optional.txt  # angr, frida, torch, mitmproxy, ...
```

| Feature | Needs | How |
|---|---|---|
| AI decompilation / summaries / Q&A | **Ollama** | `ollama serve` + `ollama pull llama3.2` |
| Ghidra decompilation | **Ghidra** | add `analyzeHeadless` to PATH or set `GHIDRA_HEADLESS` |
| RetDec decompilation | **RetDec** | add `retdec-decompiler` to PATH |
| Network capture | **mitmproxy** | `pip install mitmproxy` (provides `mitmdump`) |
| Kernel TLS capture (Linux) | **bcc** + root | `pip install -r requirements-optional-linux.txt` |
| Symbolic exec / emulation | angr / unicorn | `requirements-optional.txt` |
| Dynamic instrumentation | frida | `requirements-optional.txt` |

The **Analysis Log** tab prints a capability report on startup so you always know
which backends are active.

---

## Analyzing a single binary vs. a whole application
- **Single binary** (`.exe`, `.dll`, `.so`, `.dylib`, a Mach-O/ELF/PE): use
  **File → Open Binary**. You get disassembly, a function list (double-click to
  navigate), control-flow graphs, entropy/sections, security audit, strings/keys,
  and decompiled C *when a decompiler backend is installed*.
- **A whole app** (a folder, `.app` bundle, installer, **`.apk` / `.ipa` / `.jar`
  / `.zip`** — apps are usually *many* files): use the **Full Software** tab and
  point it at the folder or archive. It **recurses into archives** (even nested,
  shown as `app.apk!/lib.jar!/...`), classifies every file, and produces an
  **application-wide summary** plus a per-file deep dive (format, sections,
  functions, entropy, **packer/protector detection**, and embedded-secret hits).
- **Packing / protection:** known packers are detected (UPX, ASPack, VMProtect,
  Themida, Enigma, MPRESS, …). **UPX is unpacked automatically**; for heavy
  commercial protectors the tool tells you so honestly rather than pretending to
  break them.

**Honest scope:** like every RE tool (IDA, Ghidra, Binary Ninja), this recovers a
faithful *structural* understanding — disassembly, control flow, and decompiled
C — but **not** the original source with its real names and comments, and it does
not automatically defeat strong obfuscation/packing/DRM. It gives you a deep,
navigable map of what the software does; it does not magically reprint its source.

---

## Project Layout
- `main.py` — Start here!
- `src/`
  - `gui/` — All the UI magic
  - `core/` — Analysis engines, loaders, and decompilers
  - `intelligence/` — Threat intelligence and IOC extraction
  - `plugins/` — For power users and extensibility

---

## Gotchas & Tips
- **Ollama must be running locally** (`ollama serve`) for AI features.
- All the cool AI stuff is in the "AI Analysis" panel in the app.
- If you see errors about missing dependencies, double-check your Python environment and try `pip install -r requirements.txt` again.
- For network capture, make sure mitmproxy is installed and working.
- If you run into trouble, check the log tab in the GUI—it usually tells you what's wrong in plain English.

---

## Who is this for?
- Security researchers
- Students & teachers
- CTF players
- Anyone curious about how programs work under the hood

---

---

## Download & run (no Python setup)

You can use RevENG as a normal desktop app — no manual `pip install` needed.

### Option A — Pre-built app (recommended for end users)

Download the latest release for your platform from **GitHub Releases** (macOS `.zip`, Windows `.zip`, Linux `.tar.gz`). Unpack and launch:

| Platform | After download |
|---|---|
| **macOS** | Open `RevENG.app` (right-click → Open the first time if Gatekeeper blocks it) |
| **Windows** | Run `RevENG\RevENG.exe` |
| **Linux** | Run `RevENG/RevENG` |

Settings, projects, and plugins are stored in your user folder (`~/Library/Application Support/RevENG` on macOS).

To **build the standalone app yourself** from source:

```bash
# macOS / Linux
./scripts/build_release.sh

# Windows
scripts\build_release.bat
```

Maintainers can publish releases by pushing a version tag (`git tag v1.0.0 && git push origin v1.0.0`), which triggers the GitHub Actions release workflow.

### Option B — One-command source install

If you downloaded the source ZIP instead of a pre-built app:

```bash
# macOS / Linux
./scripts/install.sh
./RevENG

# Windows
scripts\install.bat
RevENG.bat
```

This creates a local `.venv`, installs all core dependencies (including the 3D CFG WebEngine viewer), and adds a launcher script.

**Note:** Heavy optional tools (Ghidra, Ollama, mitmproxy, Frida) are still installed separately — the app detects what's available and enables features accordingly.

---

<<<<<<< HEAD
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
=======
## Need Help?
- Browse the source code—it's full of helpful comments.
- Open an issue or pull request if you want to contribute or spot a bug!
- Have fun, and hack responsibly! 🚀
>>>>>>> 6f99755e16166b95c38634135adfc0b293814047
