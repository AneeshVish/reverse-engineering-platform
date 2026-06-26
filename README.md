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
- **Network Capture:**
  - Watch real HTTP/HTTPS traffic from any app (via mitmproxy).
  - Instantly spot API calls, tokens, secrets—great for bug bounties and audits.
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
open the same 14-tab workbench; pick either, then **File → Open Binary**.

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
| Symbolic exec / emulation | angr / unicorn | `requirements-optional.txt` |
| Dynamic instrumentation | frida | `requirements-optional.txt` |

The **Analysis Log** tab prints a capability report on startup so you always know
which backends are active.

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

## Need Help?
- Browse the source code—it's full of helpful comments.
- Open an issue or pull request if you want to contribute or spot a bug!
- Have fun, and hack responsibly! 🚀
