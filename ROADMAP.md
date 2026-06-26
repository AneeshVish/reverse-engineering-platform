# Roadmap: From Prototype to World-Class Reverse-Engineering Platform

This is the plan to turn the current prototype into a product that can credibly
sit next to Ghidra, IDA Pro, and Binary Ninja. It is deliberately honest: the
fastest way to lose credibility with a serious company is to overclaim. The
fastest way to win is to be **excellent and trustworthy at a focused core**, then
expand.

---

## 0. Positioning — what we are trying to be the best *at*

We will not out-Ghidra Ghidra on raw decompiler quality in year one. Our wedge is:

> **An AI-assisted, cross-platform reverse-engineering workbench that turns a raw
> binary into an explained, navigable understanding faster than anything else —
> with first-class security-audit and triage workflows built in.**

Three differentiators we can genuinely win on:
1. **AI explanation layer that is trustworthy** — every AI claim is traceable to
   the disassembly/decompilation it came from; no hallucinated confidence.
2. **Triage speed** — load → "what is this, is it malicious, what does it do,
   where are its secrets" in under a minute.
3. **Batteries-included & cross-platform** — works on macOS/Linux/Windows out of
   the box, no 10-step toolchain setup.

Everything below serves those three.

---

## Phase 1 — Trustworthy Core (Weeks 1–3)  ·  "It always works and never lies"

Goal: the load → disassemble → decompile → explain → audit path is rock solid on
PE, ELF, and Mach-O (incl. fat binaries), on all three OSes.

- **Robust loader**: magic-based detection for PE/ELF/Mach-O/fat-Mach-O/PYC/WASM
  (partially fixed already). Add architecture auto-detection (x86/x64/ARM/ARM64)
  driven by LIEF, not guesswork. Golden-file tests against `/bin/ls`, a Linux ELF,
  a Windows PE, and a packed sample.
- **Capability probe at startup**: detect Ghidra/RetDec/Ollama/mitmproxy/angr and
  disable+tooltip features that aren't available. **No feature may ever silently
  return an error string into a results pane.**
- **Structured analysis model**: keep a real in-memory model (functions, basic
  blocks, instructions, xrefs) instead of re-parsing the text of a QTextEdit for
  CFG/pseudocode/re-analyze. This is the single most important refactor.
- **Move all heavy work off the UI thread**: Ghidra/RetDec/AI all run in workers;
  the UI never freezes. (One blocking call already removed; finish the rest.)
- **Replace `print` debugging with structured logging**; ship a log panel that
  filters by level.
- **Test harness + CI**: pytest smoke + unit tests, GitHub Actions matrix
  (macOS/Linux/Windows × Py3.11/3.12), `ruff`/`black` gate.

Exit criteria: clean install + `python main.py` + load a sample + read decompiled,
explained output, on all 3 OSes, with green CI.

---

## Phase 2 — The AI Differentiator (Weeks 3–7)  ·  "Understands, doesn't guess"

This is the moat. The bar is *trustworthy* AI, not flashy AI.

- **Grounded explanations**: every AI summary cites the function/addresses it is
  describing; clicking a claim jumps to the code. Show a confidence signal and a
  "what the model could NOT determine" section.
- **Function-level pipeline**: decompile (Ghidra/RetDec/LLM4Decompile) → AI
  renames variables, adds comments, infers struct/types, flags vulns → user can
  accept/reject each suggestion (diff-style).
- **Use the strongest available model** for the explanation layer (e.g. latest
  Claude models via the Anthropic API) with local Ollama as the private/offline
  option. Make the provider pluggable and the prompts versioned in `prompt_generator`.
- **"Ask the binary"**: a chat panel scoped to the loaded program — "where is the
  license check?", "what does sub_401000 do?", "trace how this buffer is used" —
  answered with retrieval over the analysis model (RAG over functions/strings/xrefs).
- **Caching & cost control**: cache AI results per function hash; token budgeting.

Exit criteria: a non-expert can load an unknown binary and get a correct,
navigable, cited explanation of its major functions.

---

## Phase 3 — Depth & Dynamic Analysis (Weeks 7–12)  ·  "Real RE power"

- **Interactive disassembly/CFG** with cross-references, function navigation,
  renaming that propagates, and graph view (not a static text dump).
- **Decompiler quality**: integrate Ghidra headless properly (the current
  embedded script would not run as written), normalize output, and let AI refine it.
- **Dynamic analysis**: wire up the Frida integration for live hooking/tracing;
  sandbox-aware. Make the network-capture (mitmproxy) panel actually drive capture
  and correlate captured endpoints/tokens back to the binary.
- **Emulation**: optional angr/unicorn for symbolic exploration and deobfuscation.
- **Unpacking**: detect packers (PEiD signatures already present) and auto-unpack
  (UPX bundled; generic unpacker via emulation).

---

## Phase 4 — Security & Triage Workflows (Weeks 10–14)  ·  "Answers the real question"

- **Security audit, productized**: hardcoded secrets, weak crypto, dangerous APIs,
  CWE mapping, with grouped findings, severities, and patch guidance. Export to
  SARIF so it drops into existing security pipelines.
- **Threat intel**: the MalwareBazaar/OTX/ThreatMiner integration → enrich with
  reputation, YARA matching, and IOC extraction → one-click report.
- **Diffing**: binary diff between two versions (patch analysis / variant tracking).
- **Reporting**: generate a shareable HTML/PDF report of an investigation.

---

## Phase 5 — Platform, Collaboration & GTM (Weeks 14–20)  ·  "A product, not a script"

- **Project persistence** (already started in `project_storage`): save/restore an
  investigation, annotations, renames.
- **Collaboration** (the `sync_manager` stub): multi-analyst shared projects with
  comments and a merge model — a genuine gap in existing tools.
- **Plugin SDK**: stable API, docs, example plugins, a registry. Extensibility is
  how Ghidra/IDA won their ecosystems.
- **Packaging**: signed installers (PyInstaller/Briefcase) for macOS/Linux/Windows;
  auto-update.
- **Docs site, sample binaries, a 5-minute "wow" tutorial.**

---

## Cross-cutting engineering standards (start now, never stop)

- **Honesty**: no feature ships that can't be demonstrated; capability-gate the rest.
- **Tests before features**: every bug fixed gets a regression test.
- **Performance budget**: large binaries must stream/chunk; nothing blocks the UI.
- **Security of the tool itself**: it analyzes hostile input — fuzz the parsers,
  sandbox external tool execution, never `eval` untrusted data.
- **Telemetry (opt-in) + crash reporting** to learn what real users hit.

---

## What to cut / fix to stop hurting credibility (immediate)

- ✅ Removed `ultimate_file_protection/` — its "quantum-resistant" and "white-box
  AES" claims were false (random bytes / plain AES-ECB). Off-mission and a liability.
- Remove or implement every "not implemented yet" stub before a demo; a disabled,
  explained button beats a button that logs an apology.
- Make `README`/`SRS` match reality: real prerequisites, real supported platforms
  and architectures, no aspirational feature listed as present.

---

## Suggested first 2-week sprint (concrete)

1. Finish Phase 1 loader + arch auto-detect + golden-file tests. *(loader Mach-O
   detection already fixed)*
2. Startup capability probe; gate Ghidra/RetDec/Ollama/mitmproxy/AI features.
3. Move the remaining synchronous decompiler calls to workers.
4. Stand up CI (lint + smoke test on macOS/Linux/Windows).
5. Pick the AI provider, version the prompts, and ship grounded function summaries
   for one architecture as the headline demo.

Deliver that, and you have a tool that is honest, runs everywhere, and already
shows the AI differentiator — a credible "best-in-class trajectory" story for a company.
