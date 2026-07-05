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

## Need Help?
- Browse the source code—it's full of helpful comments.
- Open an issue or pull request if you want to contribute or spot a bug!
- Have fun, and hack responsibly! 🚀
