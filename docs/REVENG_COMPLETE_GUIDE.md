# RevENG — Complete Platform Guide

**Reverse Engineering Platform — full technical reference**

This document describes **everything** the RevENG application does today: what works, what is partial, what is stubbed, and what is missing. It is written for developers, security researchers, and demo reviewers who need the full picture without marketing gloss.

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Installation and running](#2-installation-and-running)
3. [Application architecture](#3-application-architecture)
4. [Welcome screen and workspaces](#4-welcome-screen-and-workspaces)
5. [Main window layout](#5-main-window-layout)
6. [Center tabs — complete reference (19 tabs)](#6-center-tabs--complete-reference-19-tabs)
7. [Dock panels and auxiliary UI](#7-dock-panels-and-auxiliary-ui)
8. [Analysis pipeline (binary load → disassembly)](#8-analysis-pipeline-binary-load--disassembly)
9. [Core engine reference (`src/core/`)](#9-core-engine-reference-srccore)
10. [Intelligence layer (`src/intelligence/`)](#10-intelligence-layer-srcintelligence)
11. [Network capture and RED-team evidence pipeline](#11-network-capture-and-red-team-evidence-pipeline)
12. [AI and decompilation backends](#12-ai-and-decompilation-backends)
13. [Plugins system](#13-plugins-system)
14. [Configuration and settings](#14-configuration-and-settings)
15. [Scripts, CLI, and API server](#15-scripts-cli-and-api-server)
16. [Testing and CI](#16-testing-and-ci)
17. [Assets, tools, and directories](#17-assets-tools-and-directories)
18. [Known limitations, stubs, and honest gaps](#18-known-limitations-stubs-and-honest-gaps)
19. [Roadmap and assessment history](#19-roadmap-and-assessment-history)
20. [Glossary](#20-glossary)

---

## 1. Executive summary

### What RevENG is

**RevENG** is a **PyQt6 desktop reverse-engineering workbench** for:

- Loading and disassembling **PE, ELF, and Mach-O** binaries
- **Decompiling** via external engines (Ghidra, RetDec, local LLM)
- **Security auditing** (secrets, weak crypto, dangerous imports)
- **Whole-application analysis** (folders, `.apk`, `.ipa`, `.jar`, nested archives)
- **Live HTTPS capture** of apps launched through a local mitmproxy
- **Server-side behavior inference** from captured API traffic
- **Evidence fusion** for authorized penetration-test style reporting

### What RevENG is not

| Claim | Reality |
|-------|---------|
| IDA Pro / Ghidra replacement | **No** — prototype workbench; decompilation quality depends on external tools |
| Recovers original source code | **No** — structural understanding (disasm, CFG, decompiled C), not original names/comments |
| Breaks commercial packers/DRM automatically | **No** — UPX may unpack; heavy protectors are detected and reported honestly |
| Universal network MITM | **No** — cert-pinned apps (WhatsApp, parts of Discord) won't decrypt without Frida |
| Phone-number location tracker | **Not in this repository** — see [§18](#18-known-limitations-stubs-and-honest-gaps) |
| Production-ready enterprise product | **No** — ambitious prototype with real components and known gaps |

### Entry point

```
main.py → Settings → PluginManager → QApplication → MainWindow
```

- **App name:** RevENG  
- **Organization:** RE-Team  
- **Primary language:** Python 3.11 / 3.12 (3.13+ may work with current wheels)

---

## 2. Installation and running

### Virtual environment (recommended)

```bash
cd reverse-engineering-platform
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

### Core dependencies (`requirements.txt`)

| Package | Role |
|---------|------|
| PyQt6, pyqtgraph | GUI and charts |
| capstone, lief, pefile | Binary load and disassembly |
| pycryptodome | Crypto helpers |
| numpy, networkx, pandas, matplotlib | Analysis and visualization |
| requests, openai | HTTP / AI client |
| qtawesome | Icons (falls back gracefully if missing) |

### Optional dependencies (`requirements-optional.txt`)

| Package | Enables |
|---------|---------|
| mitmproxy | Network Capture (`mitmdump` on PATH) |
| frida, frida-tools | Runtime Crypto / dynamic instrumentation |
| angr, unicorn, keystone-engine | Symbolic execution / emulation (mostly stubbed in UI) |
| torch, transformers | Local HuggingFace AI decompilation |
| uncompyle6 | Python bytecode decompilation |
| fastapi, uvicorn | REST API server (`src/api/server.py`) |
| GitPython | Collaboration sync (module exists, UI not wired) |
| jsbeautifier | Pretty-print minified JS from Electron ASAR |

### External CLI tools (not pip-installable)

| Tool | Feature | Install hint |
|------|---------|--------------|
| **Ghidra** `analyzeHeadless` | Ghidra decompilation | [ghidra-sre.org](https://ghidra-sre.org/) |
| **RetDec** `retdec-decompiler` | RetDec decompilation | [retdec.com](https://retdec.com/) |
| **Ollama** | Local LLM decompilation/summary | `ollama serve` + pull a model |
| **mitmproxy** `mitmdump` | Network capture | `pip install mitmproxy` |

### Capability probing

At startup, `src/core/capabilities.py` probes which backends exist. The **Analysis Log** dock prints a report. UI controls for missing backends are **disabled with tooltips** instead of failing silently.

---

## 3. Application architecture

```
main.py
├── src/utils/settings.py       config.json load/save
├── src/plugins/plugin_manager.py   loads plugins/*.py at startup
├── src/gui/main_window.py      primary controller (~2200+ lines)
├── src/gui/theme.py            global QSS themes + bundled fonts
├── src/core/*                  analysis engines (66 modules)
├── src/intelligence/*          threat intel, endpoints, pseudocode
├── src/ai/*                    prompt generation, AI assistants
├── src/collaboration/sync_manager.py   Git sync (not wired to UI)
├── src/api/server.py           optional FastAPI REST layer
├── scripts/*                   CLI tools invoked from GUI panels
└── plugins/example_plugin.py   user plugin directory
```

### Threading model

Heavy work uses **`QThread` workers** where implemented:

- `BinaryAnalysisWorker` — load + disassemble
- `DecompileWorker` — decompilation
- `AIWorker` — AI calls
- Network proof workers — TLS/WHOIS off UI thread

**Caveat:** Some Ghidra paths may still run synchronously on the UI thread in edge cases (see [§18](#18-known-limitations-stubs-and-honest-gaps)).

### Data flow (binary analysis)

```
File → Open Binary
  → UniversalLoader (LIEF)
  → DisassemblerEngine (Capstone)
  → ProgramModel (functions, basic blocks, CFG)
  → Tabs: Disassembly, Source Code, Pseudocode, Visualization, Security Audit, ...
```

### Data flow (network RED team)

```
Target app path set → Network Capture tab
  → traffic_capture.start_capture() → mitmdump + JSONL addon
  → App launched with HTTP(S)_PROXY + mitm CA env vars
  → NetworkCapturePanel reads flows
  → Enrichment: PII, secrets, trackers, server proof
  → Network Intelligence, Access Path, Server Access, Evidence Chain
```

---

## 4. Welcome screen and workspaces

On first launch, **`show_welcome_screen()`** displays a card with two buttons. Both open the **same 19-tab workbench**; they differ only in which tab is focused first.

| Button | Handler | Behavior |
|--------|---------|----------|
| **Cracking — general RE workbench** | `launch_main_ui()` | Full UI; default tab order |
| **Security — audit & secrets focus** | `launch_security_mode()` | Same UI; jumps to **Security Audit** tab |

There is **no third workspace** (e.g. Number Tracker) in the current repository tree.

After launch:

- **File → Open Binary** — load a single executable/library
- **Activity rail** (left toolbar) — quick tab shortcuts
- **⌘K / Ctrl+K** — command palette (`src/gui/command_palette.py`)

---

## 5. Main window layout

| Region | Contents |
|--------|----------|
| **Top toolbar** | Open, Re-analyze, command palette |
| **Left dock** | Explorer — sections, functions, open/re-analyze options |
| **Center** | `QTabWidget` — 19 analysis tabs |
| **Right dock** | Insights, Threat Intel, Evidence Chain, Settings |
| **Bottom dock** | Analysis Log — capability report, progress, errors |
| **Left activity rail** | Tab shortcut buttons |
| **Status bar** | Format, architecture, file size, analysis status |

---

## 6. Center tabs — complete reference (19 tabs)

### 6.1 Disassembly

| | |
|---|---|
| **File** | Inline in `main_window.py` |
| **Purpose** | Capstone disassembly text view |
| **Actions** | Download Disassembly to `.txt` |
| **Navigation** | Double-click function in Explorer → jump in disassembly |
| **Limitation** | Text-based view; not all analysis reuses structured `ProgramModel` yet |

### 6.2 Endpoint Detection

| | |
|---|---|
| **File** | Inline `QTextEdit` in `main_window.py` |
| **Engine** | `src/intelligence/endpoint_detector.py` |
| **Purpose** | Static extraction of URLs/API paths from binary strings |
| **Also shows** | Tracker domain summary via `src/core/tracker_list.py` (analytics domains — **not** phone tracking) |

### 6.3 Source Code

| | |
|---|---|
| **File** | Inline in `main_window.py` |
| **Purpose** | Decompiled C output from Ghidra / RetDec / AI |
| **Backend** | `DecompilerManager` — requires Ghidra or RetDec on PATH |
| **Limitation** | Large outputs spill to temp files (`MAX_DISPLAY_SIZE` / `MAX_DISPLAY_LINES` guards) |

### 6.4 Pseudocode

| | |
|---|---|
| **Files** | `pseudocode_toggle_widget.py` + inline view |
| **Engine** | `src/intelligence/pseudocode.py` (offline) or AI path |
| **Purpose** | Readable pseudocode with toggle between offline and AI modes |

### 6.5 AI Decompilation

| | |
|---|---|
| **File** | `advanced_viewer.py` → `AIAnalysisPanel` |
| **Engine** | `src/core/ai_decompiler.py`, Ollama or OpenAI |
| **Buttons** | Re-analyze, Enhance, Export, Summarize, Q&A |
| **Requirement** | Ollama running locally OR API key in Settings |
| **Limitation** | AI can hallucinate; not all outputs cite addresses yet (roadmap item) |

### 6.6 Visualization

| | |
|---|---|
| **File** | `advanced_viewer.py` → `AdvancedVisualizationWidget` |
| **Purpose** | CFG, entropy, call graph, memory layout (PyQtGraph / Matplotlib) |
| **Requires** | Successful disassembly / program model |

### 6.7 CFG Viewer

| | |
|---|---|
| **Files** | Tab button in `main_window.py`; widget in `cfg_viewer.py` |
| **Engine** | `src/core/cfg.py`, NetworkX |
| **Purpose** | Control-flow graph visualization |
| **Limitation** | Naive branch detection; opens separate viewer window |

### 6.8 Full Software

| | |
|---|---|
| **File** | `full_software_panel.py` |
| **Engine** | `src/core/bundle_analysis.py`, `asar.py`, `electron.py`, `protection_detector.py` |
| **Purpose** | Analyze **whole apps**: folders, `.app`, `.apk`, `.ipa`, `.jar`, `.zip` |
| **Features** | Recursive archive traversal (`app.apk!/lib.jar!/...`), per-file classification, packer detection, UPX auto-unpack, embedded secrets |
| **Honest scope** | Structural analysis — not dynamic runtime of mobile apps |

### 6.9 Crypto Tools

| | |
|---|---|
| **File** | `crypto_tools_panel.py` |
| **Scripts** | `scan_encrypted_files.py`, `analyze_crypto_routines.py`, `plot_entropy.py`, `decrypt_file.py` |
| **Also** | Certificate pinning detection on load (`cert_pin_detect.py`) |
| **Purpose** | Find encrypted files, analyze crypto routines, entropy plots, decryption attempts |

### 6.10 Key Analysis

| | |
|---|---|
| **File** | `key_analysis_panel.py` |
| **Scripts** | `find_key_strings.py`, `dump_memory_keys.py`, `dictionary_attack.py`, `brute_force_attack.py` |
| **Purpose** | Key/token string discovery, memory dump analysis, dictionary/brute-force attacks |

### 6.11 Security Audit

| | |
|---|---|
| **File** | `security_audit_panel.py` |
| **Engine** | `src/core/vuln_audit.py` |
| **Purpose** | Location-aware vulnerability map: hardcoded secrets, weak crypto imports, dangerous APIs |
| **Navigation** | Double-click finding → jump to disassembly address |
| **Security mode** | Welcome **Security** button focuses this tab |

### 6.12 Network Capture

| | |
|---|---|
| **File** | `network_capture_panel.py` |
| **Engine** | `src/core/traffic_capture.py`, `scripts/mitm_capture_addon.py` |
| **Purpose** | Launch target app through **mitmproxy**; show decrypted HTTPS API calls |
| **Sub-views** | Flow table, request/response bodies, PII tab, secrets, server evidence |
| **Auto-start** | Opening this tab with a target armed calls `auto_start()` |
| **Requirements** | `mitmdump` on PATH |
| **Limitations** | Cert-pinned apps won't decrypt; single-instance apps must be relaunched; see `PASSTHROUGH_HOSTS` in `traffic_capture.py` |

### 6.13 Network Intelligence

| | |
|---|---|
| **File** | `network_intelligence_panel.py` |
| **Bound to** | `NetworkCapturePanel` flows |
| **Sub-tabs** | Server Evidence, Behavior Inference, Behavior Timeline, Request Timeline, Behavior Metrics, Region Compare, Active Probes |
| **Engines** | `behavior_infer.py`, `behavior_timeline.py`, `behavior_metrics.py`, `region_probe.py`, `controlled_probe.py`, etc. |
| **Purpose** | Infer server architecture (gateways, LLM backends, DB leaks) from **your captured traffic only** |

### 6.14 Access Path

| | |
|---|---|
| **File** | `access_path_panel.py` |
| **Engines** | `access_path_engine.py`, `access_validator.py`, `api_base_url.py`, `engagement_scope.py` |
| **Purpose** | Discover and validate API base URLs; scope-gated probing |
| **Updates** | Refreshes when capture flows update |

### 6.15 Server Access

| | |
|---|---|
| **File** | `server_access_panel.py` |
| **Engine** | `src/core/server_access.py` |
| **Purpose** | Replay API calls with credentials harvested from captured flows |
| **Warning** | **Authorized testing only** — gated by engagement scope |

### 6.16 Privesc Surface

| | |
|---|---|
| **File** | `privesc_panel.py` |
| **Engine** | `src/core/privesc_surface.py` |
| **Purpose** | Static privilege-escalation attack surface (setuid, entitlements, dylib paths) |

### 6.17 Threats

| | |
|---|---|
| **File** | `threat_lab_panel.py` |
| **Engine** | `src/core/threat_lab.py` |
| **Purpose** | Benign MITRE ATT&CK-style **local simulations** (EICAR-style sandbox tests, localhost sinks) |
| **Not** | Real malware execution |

### 6.18 Runtime Crypto

| | |
|---|---|
| **File** | `runtime_crypto_panel.py` |
| **Engine** | `src/core/runtime_crypto.py`, `resign.py` |
| **Purpose** | Frida hooks on CommonCrypto / OpenSSL / BoringSSL + TLS plaintext boundary |
| **macOS** | Can re-sign `.app` copies with `get-task-allow` for instrumentation |
| **Requires** | `frida` package + Frida server on target where applicable |

### 6.19 Project Analysis

| | |
|---|---|
| **File** | `project_analysis_tab.py` |
| **Engine** | `src/utils/project_storage.py`, `src/ai/prompt_generator.py` |
| **Purpose** | Save/load investigation projects; generate versioned LLM prompts for reconstruction |

---

## 7. Dock panels and auxiliary UI

### 7.1 Explorer (left dock)

- Open binary, section tree, function tree
- Analysis checkboxes (entropy, strings, etc.)
- Function double-click → disassembly navigation

### 7.2 Insights (`insights_panel.py`)

At-a-glance binary stats: format, architecture, protection verdict, secret hits, section summary.

### 7.3 Threat Intel (inline in `main_window.py`)

- **Engine:** `src/intelligence/threat_intel.py`
- Queries **MalwareBazaar**, **ThreatMiner**, **AlienVault OTX**
- IOC tree from `IOCExtractor`
- **Limitation:** MISP integration logs "not implemented yet" in some paths

### 7.4 Evidence Chain (`evidence_chain_panel.py`)

- **Engines:** `evidence_store.py`, `evidence_fusion.py`, `target_profile.py`
- Fuses STATIC / LIVE / HEADERS / PROBES layers
- HTML export via `engagement_report.py`

### 7.5 Settings (inline)

- Theme selection (persisted to `config.json`)
- Ollama model, API key, entropy display toggle
- **Note:** Settings defaults in code may differ from committed `config.json` (merged on load)

### 7.6 Analysis Log (bottom dock)

- Capability probe output
- Analysis progress and errors
- Download log to file

### 7.7 Supporting GUI modules (not primary tabs)

| File | Role |
|------|------|
| `theme.py` | Tokyo Night, Enterprise Slate, etc.; bundled JetBrains Mono + Inter |
| `icons.py` | qtawesome with no-op fallback |
| `command_palette.py` | Fuzzy command launcher |
| `views.py` | Legacy `DisassemblyView`, `PluginView` — not main tab path |
| `unified_viewer.py` | Hex/Disasm/Structure viewer — used in tests |
| `cfg_viewer.py` | Matplotlib CFG widget |

---

## 8. Analysis pipeline (binary load → disassembly)

1. **User:** File → Open Binary  
2. **`BinaryAnalysisWorker`** (background thread):
   - `UniversalLoader.load()` — LIEF PE/ELF/Mach-O or RAW fallback
   - Section extraction
   - Architecture detection from LIEF headers
   - `DisassemblerEngine.initialize(arch)` + disassemble
3. **`on_analysis_complete`**:
   - Populate disassembly view
   - Build `ProgramModel` where implemented
   - Trigger endpoint detection, insights, security audit
   - Optional Ghidra decompile (if installed)
4. **Protection handling:**
   - `protection_detector.py` / `protection_verdict.py` — packer detection
   - UPX may auto-unpack via `unpacker.py`
   - Commercial protectors → honest "not broken" verdict

---

## 9. Core engine reference (`src/core/`)

66 modules. Grouped by domain.

### 9.1 Loading and binary format

| Module | Purpose | Limitations |
|--------|---------|-------------|
| `universal_loader.py` | LIEF-based PE/ELF/Mach-O/RAW | RAW is best-effort |
| `binary_loader.py` | Legacy loader | Overlaps with universal_loader |
| `novel_binary_parser.py` | Custom formats via YAML signatures | Small signature set |
| `binary_signatures.yaml` | Magic bytes | Example magics only |
| `unpacker.py` | Basic unpacking | UPX-oriented |
| `protection_detector.py` | Packer/protector detect + UPX unpack | No commercial protector breaking |
| `protection_verdict.py` | Encrypted vs compressed vs obfuscated | Heuristic |
| `peid_signatures.py` | PEiD-style sigs | **Tiny demo DB**, not full PEiD |

### 9.2 Disassembly and program model

| Module | Purpose | Limitations |
|--------|---------|-------------|
| `disassembler.py` | Capstone wrapper | Must call `initialize(arch)` |
| `multiarch_disassembler.py` | Extended arch support | Parallel to main disassembler |
| `enhanced_disassembler.py` | Extra analysis | Less used |
| `program_model.py` | Functions, basic blocks, CFG edges | Not all UI paths use it yet |
| `cfg.py` | NetworkX CFG from instructions | Naive branch detection |

### 9.3 Decompilation

| Module | Purpose | Limitations |
|--------|---------|-------------|
| `decompiler_manager.py` | Orchestrates Ghidra/RetDec/AI engines | Engines are external |
| `decompiler.py`, `decompiler_advanced.py` | Interfaces / extended pipeline | Framework-level |
| `ai_decompiler.py` | Ollama / HuggingFace | Needs running Ollama or GPU stack |
| `python_decompiler.py` | Python bytecode | Old bytecode only (uncompyle6) |

### 9.4 Security audit and privesc

| Module | Purpose |
|--------|---------|
| `vuln_audit.py` | Secrets, weak crypto, dangerous imports, xrefs |
| `privesc_surface.py` | setuid, entitlements, dylib hijack paths |
| `cert_pin_detect.py` | Certificate pinning heuristics |

### 9.5 Whole-app / bundle analysis

| Module | Purpose |
|--------|---------|
| `bundle_analysis.py` | Recursive APK/IPA/JAR/ZIP analysis |
| `asar.py` | Electron ASAR extraction |
| `electron.py` | Electron bundle helpers |
| `client_architecture_intel.py` | DB/queue/auth keyword extraction from text |
| `architecture_lexicon.py` | Technology keyword taxonomy |

### 9.6 Network capture and evidence

| Module | Purpose |
|--------|---------|
| `traffic_capture.py` | mitmdump lifecycle, env CA trust, app launch, macOS system proxy |
| `streaming_capture.py` | SSE/WebSocket parsing, token extraction |
| `pii_classify.py` | Email, device IDs, GPS fields in bodies |
| `tracker_list.py` | **Analytics/ad tracker domains** (Google, Facebook, etc.) in HTTP traffic |
| `tls_identity.py` | TLS cert + WHOIS ownership proof |
| `server_proof.py` | Production signals (cf-ray, trace headers) from captured traffic |
| `endpoint_rank.py` | Rank static vs live endpoints |
| `endpoint_correlation.py` | Static ↔ live correlation |
| `api_base_url.py` | Pick API base URL heuristically |
| `live_connections.py` | `lsof`-based live sockets |
| `network_intel.py` | DNS resolution, local IPs |
| `network_fingerprint.py` | DNS/TLS/cloud infrastructure hints |
| `behavior_infer.py` | Server behavior inference from headers/bodies |
| `behavior_timeline.py` | Action → request timeline |
| `behavior_metrics.py` | TTFT, rate limits, retries |
| `request_correlation.py` | Trace/correlation ID linking |
| `auth_lifecycle.py` | Login → token → refresh mapping |
| `telemetry_parser.py` | Datadog/Sentry/GA parsing |
| `controlled_probe.py` | Scope-gated error probes |
| `region_probe.py` | Multi-region cf-ray/latency compare |
| `function_request_correlation.py` | Frida ↔ mitm event matching |
| `ui_event_capture.py` | Desktop UI action hooks (partial) |

### 9.7 Server access and engagement

| Module | Purpose |
|--------|---------|
| `server_access.py` | API replay with harvested credentials |
| `access_path_engine.py` | Server entry point discovery |
| `access_validator.py` | Scope-gated path validation |
| `engagement_scope.py` | Rules of engagement, audit log |
| `staging_session.py` | Client-provided staging auth |
| `engagement_report.py` | HTML client report export |
| `evidence_store.py` | Session evidence graph |
| `evidence_fusion.py` | Merge evidence layers with confidence |
| `blue_team.py` | Hardening recommendations from RED evidence |
| `target_profile.py` | Unified session object |
| `re_session.py` | Orchestrate resign + mitm + Frida (experimental) |

### 9.8 Dynamic / runtime

| Module | Purpose | Limitations |
|--------|---------|-------------|
| `runtime_crypto.py` | Frida crypto + TLS hooks | Requires frida |
| `resign.py` | macOS app re-sign for debugging | macOS only |
| `debugger.py` | Debug engine enum | Minimal |
| `process_monitor.py` | Child processes, SQLite | Basic |
| `advanced_unpacking.py` | angr/Frida/Qiling unpack | **Most paths are STUB loggers** |

### 9.9 Misc

| Module | Purpose |
|--------|---------|
| `threat_lab.py` | Benign ATT&CK simulations |
| `capabilities.py` | Runtime backend probing |
| `https_client.py` | Probe HTTP client with certifi |

---

## 10. Intelligence layer (`src/intelligence/`)

| Module | Purpose |
|--------|---------|
| `threat_intel.py` | MalwareBazaar, ThreatMiner, OTX API integration |
| `endpoint_detector.py` | Static URL/API path extraction from binaries |
| `pseudocode.py` | Offline pseudocode generation |

---

## 11. Network capture and RED-team evidence pipeline

### How capture works

1. User sets target binary/app path (from loaded binary or Full Software)
2. **Network Capture** tab opened → `auto_start()` if target armed
3. `traffic_capture.start_capture()`:
   - Picks port (default 8080 or free port)
   - Starts `mitmdump -s scripts/mitm_capture_addon.py`
   - Sets `HTTP_PROXY`, `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, etc.
   - Launches target subprocess
4. Addon writes JSONL to path in `RE_CAPTURE_FILE`
5. Panel polls/tails JSONL → enriches each flow

### Enrichment per flow

- **PII** — `pii_classify.py`
- **Secrets** — Bearer, JWT, API key regexes
- **Trackers** — `tracker_list.py` domain classification
- **Server proof** — `tls_identity.py`, `server_proof.py`

### Passthrough hosts (not MITM'd)

Defined in `traffic_capture.py` — includes Apple push/update, Discord, WhatsApp, Google update hosts. These apps **keep working** but traffic is **not decrypted**.

### Downstream consumers

When flows update, signals connect to:

- Access Path (base URL refresh)
- Server Access (credential harvest refresh)
- Evidence Chain (fusion refresh)
- Network Intelligence (behavior analysis refresh)

### Demo without GUI

```bash
python golden_path_demo.py    # Headless RED pipeline validation
python demo_traffic.py        # Synthetic HTTPS client for capture testing
```

---

## 12. AI and decompilation backends

### Priority order (typical)

1. **Ghidra** — `analyzeHeadless` on PATH or `GHIDRA_HEADLESS` env
2. **RetDec** — `retdec-decompiler` on PATH
3. **Ollama** — local LLM at `http://localhost:11434`
4. **OpenAI / API** — key in Settings or `.env`

### AI features in UI

- AI Decompilation tab — re-analyze, enhance, summarize, Q&A
- Pseudocode toggle — offline vs AI
- Project Analysis — prompt generation for reconstruction

### Honest AI limitations

- Outputs may **hallucinate** function purpose or names
- Not all AI claims link back to addresses yet (ROADMAP Phase 2)
- Large models need GPU / Ollama running locally

---

## 13. Plugins system

### Location

- Default directory: `plugins/` (config: `directories.plugin_dir`)
- Example: `plugins/example_plugin.py`

### Hook interface (`src/plugins/base_plugin.py`)

| Hook | When (designed) |
|------|-----------------|
| `on_load` | Plugin loaded |
| `on_unload` | Plugin unloaded |
| `on_binary_load` | Binary opened |
| `on_disassembly` | Disassembly complete |
| `on_analysis` | Analysis complete |

### Integration status — **important**

| Fact | Status |
|------|--------|
| Plugins load at startup | ✅ Yes (`main.py` → `PluginManager.load_plugins()`) |
| `plugin_manager` stored on `MainWindow` | ✅ Yes |
| `execute_hook()` called from analysis pipeline | ❌ **No** — hooks registered but **never fired** from `main_window.py` |
| REST API plugin analyze | ✅ `POST /plugin/analyze` in `src/api/server.py` |
| `PluginView` in `views.py` | Exists but not primary UI |

**Bottom line:** Plugins load and can be invoked via the optional REST API, but **the GUI analysis pipeline does not call plugin hooks today**.

---

## 14. Configuration and settings

### `config.json` (committed example)

```json
{
  "general": {
    "theme": "Enterprise Slate",
    "font_family": "Consolas",
    "font_size": 9,
    "auto_save": true
  },
  "directories": {
    "plugin_dir": "plugins",
    "project_dir": "projects",
    "temp_dir": "temp"
  },
  "disassembly": {
    "show_bytes": true,
    "show_addresses": true,
    "syntax_highlighting": true,
    "auto_analyze": true
  },
  "debugger": {
    "auto_attach": false,
    "default_timeout": 30,
    "log_api_calls": true
  },
  "ai": {
    "enabled": false,
    "api_key": "",
    "model": "gemma3",
    "max_tokens": 1000,
    "ollama_endpoint": "http://localhost:11434/api/generate",
    "use_ollama": true,
    "ollama_stages": 3
  }
}
```

### Settings API (`src/utils/settings.py`)

- `Settings.load()` / `Settings.save()` — merge with defaults
- `get(category, key)` — read values
- Theme persisted via GUI Settings tab

### Environment (`.env.example`)

- `OPENAI_API_KEY`, `OLLAMA_HOST`, `OLLAMA_PORT`

---

## 15. Scripts, CLI, and API server

### Root scripts

| Script | Purpose |
|--------|---------|
| `main.py` | Launch GUI |
| `demo_traffic.py` | Synthetic HTTPS for capture demo |
| `golden_path_demo.py` | Headless RED-team pipeline test |

### `scripts/` (invoked from GUI via `src/utils/paths.script_path`)

| Script | Used by |
|--------|---------|
| `mitm_capture_addon.py` | mitmproxy capture |
| `find_key_strings.py` | Key Analysis |
| `dump_memory_keys.py` | Key Analysis |
| `dictionary_attack.py` | Key Analysis |
| `brute_force_attack.py` | Key Analysis |
| `scan_encrypted_files.py` | Crypto Tools |
| `analyze_crypto_routines.py` | Crypto Tools |
| `plot_entropy.py` | Crypto Tools |
| `decrypt_file.py` | Crypto Tools |
| `security_audit.py` | Standalone audit |
| `image_to_bin.py` | Utility |
| `build_py_disasm_dataset.py` | Dataset builder |
| `setup_complete.py` | Setup helper |

### Optional REST API

```bash
pip install fastapi uvicorn
python src/api/server.py    # listens on :8000
```

| Endpoint | Purpose |
|----------|---------|
| `GET /status` | Health check |
| `POST /decompile` | Decompile assembly snippet |
| `GET /plugins` | List loaded plugins |
| `POST /plugin/analyze` | Run plugin `analyze()` |

### Shell utilities

| File | Purpose |
|------|---------|
| `ship.sh` | Local verify + git push automation |
| `install_research_tools.ps1` | Windows tool installer |
| `fix_libmagic.ps1` | Windows libmagic fix |

---

## 16. Testing and CI

### Test suite

**36 test files** under `tests/`, run via `pytest`.

| Area | Test files (examples) |
|------|------------------------|
| GUI smoke | `test_panels.py`, `test_app_builds.py`, `test_theme.py` |
| Loader / disasm | `test_loader.py`, `test_disassembler.py`, `test_program_model.py` |
| Bundle / protection | `test_bundle_analysis.py`, `test_protection_and_archives.py` |
| Network | `test_traffic_capture.py`, `test_capture_pipeline.py`, `test_streaming_capture.py` |
| Evidence / behavior | `test_evidence_layer.py`, `test_behavior_infer.py`, `test_server_proof.py` |
| Security | `test_vuln_audit.py`, `test_privesc_surface.py`, `test_runtime_crypto.py` |
| Access / server | `test_access_path_engine.py`, `test_server_access.py` |

### CI (`.github/workflows/ci.yml`)

- **Matrix:** Ubuntu + macOS × Python 3.11, 3.12
- **Headless Qt:** `QT_QPA_PLATFORM=offscreen`
- **Blocking lint:** `ruff check --select E9,F63,F7,F82`
- **Style lint:** non-blocking full ruff
- **Not in CI:** Ghidra, RetDec, mitmproxy E2E with real apps, Frida on device

---

## 17. Assets, tools, and directories

| Path | Contents |
|------|----------|
| `assets/fonts/` | JetBrains Mono, Inter (bundled) |
| `assets/screenshots/` | UI screenshots |
| `tools/upx-5.0.1-win64/` | Bundled UPX (Windows) |
| `plugins/` | User plugins |
| `projects/`, `temp/` | Referenced in config; created on use |
| `logs/` | Log output |
| `decompiled_projects/` | Decompilation output (may be empty) |
| `tests/fixtures/` | Test artifacts |

**No top-level `data/` directory** in the current tree.

---

## 18. Known limitations, stubs, and honest gaps

### 18.1 Product-level

- **Prototype**, not production IDA/Ghidra replacement (see `ROADMAP.md`)
- Does **not** recover original source names/comments
- Does **not** automatically defeat strong obfuscation/DRM/commercial packers
- **`ultimate_file_protection/` removed** — previously contained false "quantum-resistant" claims

### 18.2 Feature gaps

| Item | Status |
|------|--------|
| Plugin hooks in GUI pipeline | **Loaded, never executed** |
| Collaboration / Git sync UI | Module exists; **checkbox not wired** |
| `advanced_unpacking.py` | **Stub loggers** for angr/Frida/Qiling |
| MISP threat intel | "Not implemented yet" in some code paths |
| README "14-tab workbench" | **Outdated** — actually **19 center tabs** |
| Structured instruction model | **Partial** — some views re-parse disassembly text |
| Ghidra on UI thread | Some paths may still block (should move to workers) |
| Export analysis | Only if `last_analysis_results['analysis_log']` populated |

### 18.3 Network capture limits

- **Certificate pinning** — native pinned apps won't decrypt without Frida TLS hooks
- **Single-instance apps** — must quit and relaunch under proxy
- **macOS system capture** — may need admin for system proxy + CA trust
- **E2E encrypted apps** (WhatsApp) — uncapturable by design; passthrough to avoid breaking app

### 18.4 What is NOT in this repository

The following were discussed in some development branches/conversations but **are not present in the current codebase**:

| Feature | Status in repo |
|---------|----------------|
| **Number Tracker workspace** | ❌ Not present — no `number_tracker_window.py`, no welcome button |
| **Signal convergence / MSISDN spectral engine** | ❌ Not present |
| **Companion Android app** | ❌ No `companion/android/` directory |
| **Phone locate / ingest server for MSISDN** | ❌ Not present |
| **`number_tracker` section in config.json** | ❌ Not in committed config |

### 18.5 `tracker_list.py` — naming clarification

**`src/core/tracker_list.py` is NOT phone-number tracking.**

It classifies **third-party analytics/ad tracker domains** (Google Analytics, Facebook Pixel, etc.) found in **captured HTTP traffic**. It answers: "Is this app phoning home to known trackers?" — not "Where is this phone number?"

---

## 19. Roadmap and assessment history

### ROADMAP.md (summary)

Phased plan from prototype to credible workbench:

1. **Phase 1 — Trustworthy core** — robust loader, capability probe, structured model, workers, CI
2. **Phase 2 — AI differentiator** — grounded explanations, function pipeline, RAG chat
3. **Phase 3+** — collaboration, plugins, enterprise features

Positioning wedge: **AI-assisted triage speed** with honest security audit — not raw decompiler superiority over Ghidra on day one.

### ASSESSMENT_REPORT.md (2026-06-26)

Historical pre-demo review noting:

- Two divergent repo copies (git vs Downloads) — consolidation needed
- Multiple crash fixes applied on `consolidate-and-fix` branch
- App described as **ambitious unfinished prototype**
- Core static analysis path can be made demo-worthy with focused work

**Note:** Many Phase 0–1 fixes from that report have since landed (capability gating, cross-platform open, ARM support, optional requirements split, 36 test files, CI). Re-read the report for historical context, not current truth.

---

## 20. Glossary

| Term | Meaning in RevENG |
|------|-------------------|
| **RE** | Reverse engineering |
| **CFG** | Control-flow graph |
| **MITM** | Man-in-the-middle HTTPS interception via mitmproxy |
| **LIEF** | Library for parsing PE/ELF/Mach-O |
| **Capstone** | Disassembly engine |
| **ASAR** | Electron archive format |
| **IOC** | Indicator of compromise (threat intel) |
| **PII** | Personally identifiable information in HTTP bodies |
| **Tracker (network)** | Analytics/ad domain in HTTP traffic — see `tracker_list.py` |
| **Engagement scope** | Rules-of-engagement gate for probes and server access |
| **Evidence fusion** | Merging static binary + live capture + probe results |

---

## Quick reference — file counts

| Area | Count |
|------|-------|
| GUI Python files | 23 in `src/gui/` |
| Core Python files | 66 in `src/core/` |
| Test files | 36 in `tests/` |
| Center tabs | 19 |
| Welcome workspaces | 2 (same workbench) |

---

## Document maintenance

- **Generated for:** RevENG reverse-engineering-platform repository  
- **Reflects:** Current tree as of documentation pass  
- **When updating:** Re-count tabs in `main_window.create_center_panel()`, re-run `pytest`, re-read `capabilities.py` and `ROADMAP.md`

If you add Number Tracker or other workspaces later, add a new top-level section here rather than assuming this doc auto-updates.

---

## 21. Target architecture (evolution plan)

See **[ARCHITECTURE_TARGET.md](ARCHITECTURE_TARGET.md)** for annotated diagrams.

### Dual TLS capture plane

| Plane | Module | When |
|-------|--------|------|
| Userspace proxy | `traffic_capture.py` + mitm addon | Electron, CLI, launched apps |
| Userspace hooks | `runtime_crypto.py` + Frida | Certificate-pinned native apps |
| Kernel (Linux) | `ebpf_capture/sniffer.py` | OpenSSL/BoringSSL without binary modification |

All planes normalize to **`PlaintextEvent`** → `plaintext_bus.py` → Network Capture + EvidenceStore.

### MCGD decompilation (`src/core/mcgd/`)

- **L1** `parser_agent.py` — Tree-sitter syntax (fallback: brace balance)
- **L2** `compiler_agent.py` — gcc -c stderr
- **L3** `execution_agent.py` — differential exec vs original binary
- **Orchestrator** — max 5 iterations; reward R(C_d) in `rewards.py`
- Wired after full decompilation in `main_window._run_mcgd_validation()`

### Virtual UI

- **Disassembly:** `DisasmView` + `VirtualDisasmModel` (replaces QTextEdit cap)
- **CFG:** `cfg_web_viewer.py` for graphs >200 nodes; matplotlib fallback for small graphs

### Plugin hooks (now executed)

`plugin_manager.execute_hook('on_binary_load'|'on_disassembly'|'on_analysis')` in `on_analysis_complete`.

### MCP analysis server

`src/api/mcp_server.py` — tools: list_functions, get_program_stats, list_capture_events, run_mcgd.
