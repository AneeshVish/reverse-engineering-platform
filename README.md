# Ultimate Reverse Engineering Platform

## Overview
The Ultimate Reverse Engineering Platform is an all-in-one, privacy-respecting tool for static and dynamic analysis of binaries and applications. It combines:
- **AI-powered decompilation** (LLM-based)
- **Integrated network capture** (mitmproxy backend)
- **Security audit with grouped findings and patch recommendations**
- **Key/token extraction**
- **Modern PyQt6 GUI**

This platform is ideal for security researchers, students, and educators who want to analyze, audit, and demonstrate vulnerabilities in real-world software.

---

## Features
- **AI Decompilation:**
  - Converts disassembly to high-level code using local LLMs (e.g., Ollama, LLM4Decompile).
  - Results shown in the "Source Code" tab.

- **Network Capture:**
  - Capture HTTP/HTTPS traffic from any application using mitmproxy.
  - Extracts API calls, tokens (JWT, Bearer, OAuth, etc.), and displays them in real time.
  - Manual control for start/stop capture to ensure privacy.

- **Security Audit:**
  - Scans binaries for hardcoded secrets, weak algorithms, tokens, and master keys.
  - Groups findings by type and provides clear patch recommendations.
  - Detects hashes and attempts to recover plaintext for common secrets.

- **Key/Token Extraction:**
  - Finds likely cryptographic keys, master keys, and tokens in binaries and scripts.
  - Attempts to identify hashes and decrypt or crack them with demo wordlists.

- **Modern GUI:**
  - PyQt6 interface with tabs for Disassembly, Source Code, Pseudocode, Security Audit, Network Capture, and more.
  - Log view for real-time feedback and error reporting.

## Requirements
Install dependencies with:
```bash
pip install -r requirements.txt
```

## Running the Application
From the root of the project:
```bash
python main.py
```

## Deployment
To build a standalone executable (optional):
```bash
pip install pyinstaller
pyinstaller --onefile main.py
```
The generated executable will be in the `dist/` folder.

## OpenAI API Key
- The platform uses a hardcoded OpenAI API key for development and testing.
- **WARNING:** Remove the hardcoded key from the code before sharing or deploying.
- You can also set your own API key in the settings panel at runtime.

## Project Structure
- `main.py` — Entry point
- `src/` — All application code
  - `gui/` — UI components
  - `core/` — Core analysis and decompilers
  - `intelligence/` — Threat intelligence modules
  - `plugins/` — Plugin system

## Notes
- Ollama must be running locally (`ollama serve`) to use local LLM features.
- All major AI features are available from the AI Analysis Panel in the UI.


---

For more details or troubleshooting, see the source code and comments.
