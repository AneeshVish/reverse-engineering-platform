# Reverse Engineering Platform — Technical Assessment Report

**Date:** 2026-06-26
**Reviewer:** Engineering assessment (pre‑demo readiness review)
**Scope:** Two trees were reviewed and compared:

- **Working repo (git):** `/Users/ani/Projects/Reverse Engg/reverse-engineering-platform`
- **"Full" copy (Downloads):** `/Users/ani/Downloads/reverse-engineering-platform`

---

## ⏱ Remediation status (branch `consolidate-and-fix`)

The first two phases of the plan in §7 have been executed on this branch:

**Phase 0 — Consolidation & hygiene — DONE**
- Downloads copy adopted as source of truth (8 missing modules brought in, incl. the previously-missing `pseudocode_toggle_widget.py` that broke startup).
- `ultimate_file_protection/` (the fake-crypto subsystem) excluded from the product.
- Stale root duplicates removed (`test.py`, root `example_plugin.py`, `image_to_bin.py`, `setup_complete.py` — the latter two now live under `scripts/`).
- Committed `.pyc`/cache files untracked; generated artifacts (`encrypted_files_report.json`, `*.log`, `logs/`) untracked and gitignored.
- `requirements.txt` de-duplicated and split into core vs `requirements-optional.txt`; Python 3.11/3.12 documented as the supported target.

**Phase 1 — Crash fixes — DONE** (whole tree now byte-compiles clean)
- §3 #4: `MAX_DISPLAY_SIZE` / `MAX_DISPLAY_LINES` now defined as module constants.
- §3 #5: `run_full_decompilation` fixed — `self.decompile_view`→`self.source_code_view` (×11), bare `ai_decompiler`→`self.ai_decompiler`.
- §3 #6: worker-start indentation (already correct in the Downloads copy).
- §3 #7: removed the synchronous `decompile_parallel` UI-thread call (up to 5-min freeze, returned nothing usable).
- §3 #8: `os.startfile` (Windows-only) replaced with a cross-platform `open_path_externally()` helper (×4).
- §3 #9: `Architecture.ARM` / `ARM64` added to the disassembler enum + `initialize()`.
- §3 #10: `torch` lazy-import (already fixed in the Downloads copy).

**Not yet done / still open:** Phase 2–3 (capability probing for Ghidra/RetDec/Ollama/mitmproxy, structured-instruction model, real export, smoke tests, doc pass). The synchronous `_run_ghidra()` call in `on_analysis_complete` is left in place (it fails fast when Ghidra is absent) but should be moved off the UI thread in Phase 2. **The app could not be launched in this environment** (Python 3.14, no GUI deps installed) — verification was by byte-compilation + static analysis; a runtime smoke test on Python 3.12 with deps installed is still required.

---

## 0. Executive Summary (read this first)

This is an **ambitious but unfinished prototype**, not a production reverse‑engineering tool. The architecture and feature list are genuinely impressive on paper (multi‑engine decompilation, AI assist, threat intel, network capture, crypto/key analysis), and several low‑level pieces are real and work (Capstone disassembly, LIEF loading, threat‑intel API calls). **But the application as a whole does not currently run end‑to‑end**, the GUI controller (`main_window.py`) contains multiple hard crashes, and a large fraction of advertised features are stubs, shell‑outs to tools that must be installed separately, or — in the `ultimate_file_protection` add‑on — **security theater with false claims** ("quantum‑resistant", "white‑box AES") that should not be shown to a security‑literate company as‑is.

**Verdict for a company demo:** Not ready. With ~1–2 weeks of focused work the *core* static‑analysis path (load → disassemble → view → security audit) can be made genuinely solid and demo‑worthy. The honest pitch should be "AI‑assisted static analysis workbench," and the overreaching/fake parts should be cut or clearly labeled.

### Which copy is the "real" one?
The **Downloads copy is the fuller and more‑fixed version.** Evidence:
- It contains 8 modules the git repo lacks (see §1).
- Its `main_window.py` is larger (1356 vs 1182 lines) and has **fixed two bugs** still present in the git repo: the duplicate `on_decompile_complete` method and the missing `on_model_changed`/`index` handler.
- Recommendation: **make Downloads the source of truth**, bring it into git, then fix from there. Do *not* keep maintaining both.

---

## 1. What exists where (tree delta)

Modules present **only in the Downloads copy** (missing from git working repo):

| Module | Purpose |
|---|---|
| `src/core/novel_binary_parser.py` | Custom/unknown binary format parsing |
| `src/intelligence/endpoint_detector.py` | API endpoint extraction |
| `src/utils/project_storage.py` | Save/load analysis projects |
| `src/ai/prompt_generator.py` | LLM prompt construction |
| `src/gui/pseudocode_toggle_widget.py` | AI/offline pseudocode toggle (referenced by main_window!) |
| `src/gui/project_analysis_tab.py` | Project-level analysis tab |
| `src/plugins/examples/example_plugin.py` | Plugin example |
| `ultimate_file_protection/` (13 modules) | A separate file‑*obfuscation* product (see §5) |

> **Critical:** the git working repo's `main_window.py` imports `src.gui.pseudocode_toggle_widget`, which **does not exist in that tree**. So the git copy cannot even build its center panel — it will throw on startup. This alone confirms the git repo is the "half" version.

Nearly **every shared `.py` file differs** between the two trees — they diverged independently. Consolidation is required.

---

## 2. What actually works (the real assets)

These components are real, correctly implemented, and worth keeping:

- **Disassembly engine** — `src/core/disassembler.py`. Clean Capstone wrapper, chunked, `skipdata=True`, self‑tests on init. Solid. *(Limitation: only x86/x86‑64; see §3.)*
- **Universal loader** — `src/core/universal_loader.py`. Reasonable LIEF‑based PE/ELF/Mach‑O detection with magic‑byte fallback and graceful RAW fallback.
- **Threat intelligence** — `src/intelligence/threat_intel.py`. Genuinely calls MalwareBazaar / ThreatMiner / AlienVault OTX public APIs and normalizes a reputation score. Works given network access.
- **Security‑hardening already done** — hardcoded OpenAI key was removed (commit `1a44e6d`); key now comes from the Settings tab / `.env`. Good.
- **GUI shell & styling** — the PyQt6 layout, dark theme, tabbed workbench, and worker‑thread pattern (`QThread`) are well structured.
- **Multi‑engine decompiler orchestration** — `decompiler_manager.py` parallel `ThreadPoolExecutor` design is sound *as a framework* (the engines themselves are external; see §4).

---

## 3. Bugs that crash or break features (must‑fix)

All line numbers are in the **git working** `src/gui/main_window.py` unless noted. Items marked ✅Downloads are already fixed in the Downloads copy.

1. **Missing module breaks startup (git copy only).** `from src.gui.pseudocode_toggle_widget import PseudocodeToggleWidget` (line ~378) — file absent in git tree. → use Downloads copy.

2. **`on_model_changed` uses undefined `index`.** Line ~473: `model_type_map.get(index, ...)` — `index` is never a parameter. Changing the AI model in Settings raises `NameError`. ✅Downloads fixed.

3. **Duplicate `on_decompile_complete`.** Defined twice (lines ~737 and ~879); the second silently overrides the first, so the large‑output/RetDec‑first logic is dead code. ✅Downloads fixed.

4. **`MAX_DISPLAY_SIZE` / `MAX_DISPLAY_LINES` never defined.** Referenced in `run_full_decompilation` (lines ~694, ~714) **and still in the Downloads copy** (lines ~1015, ~1035). Any large decompilation output path raises `NameError`. **Not fixed anywhere.**

5. **`run_full_decompilation` references undefined names.** Uses `ai_decompiler` (should be `self.ai_decompiler`) and `self.decompile_view` (the widget is `self.source_code_view`). The whole "Full Binary C Decompilation" menu action throws.

6. **`DecompileWorker.start()` runs even when AI is disabled.** In `on_analysis_complete` the `self.decompile_worker = ...` assignment is inside `if self.ai_decompile_cb.isChecked():` but the `.connect()/.start()` calls are dedented outside it → `AttributeError` when the checkbox is off.

7. **Heavy work on the UI thread.** `on_analysis_complete` calls `decompiler_manager._run_ghidra(...)` (a 120 s subprocess) directly on the main thread → UI freezes/"not responding" on every file load.

8. **`os.startfile` is Windows‑only.** Used in several places (log open, output open). On macOS/Linux (this machine is macOS) it raises `AttributeError`. SRS even claims Windows‑primary, but the repo is being run on Darwin.

9. **`Architecture.ARM` / `ARM64` don't exist** in `disassembler.py` (enum has only `X86`, `X86_64`), yet `main_window` branches on them → `AttributeError` for ARM inputs. (A separate `multiarch_disassembler.py` exists and should be the single source of truth.)

10. **`ai_decompiler.py` hard‑imports `torch` at module top** (git copy). If `torch` isn't installed, even *Ollama* mode fails to import. ✅Downloads moves the torch import into the HuggingFace branch.

---

## 4. Features that are "wired but hollow" (depend on uninstalled external tools or are stubs)

These won't work out of the box and need either bundling, clear preconditions, or honest labeling:

- **Ghidra decompilation** — shells out to `analyzeHeadless` on `PATH`. Not installed/bundled → always returns an error string. The embedded Ghidra script is also Java written into a `.java` temp file but invoked as a post‑script (Ghidra post‑scripts are `.py`/`.java` GhidraScript classes, not free Java) — it would not run as written.
- **RetDec decompilation** — shells out to `retdec-decompiler`. Not bundled.
- **AI decompilation** — requires a local **Ollama** server + pulled model (`llama3.2`/`llama3`), or a HuggingFace 6.7B model download (~13 GB) + `torch`. None present by default.
- **Network capture** — README claims mitmproxy backend; verify the panel actually drives mitmproxy (the capture log file is empty).
- **Stubs that only log "not implemented":** `enhance_with_ai_comments`, `ask_ai_about_code`, `configure_misp`, `export_iocs`, `export_analysis` (no real export). The **Collaboration** tab is a "coming soon" label; `sync_manager.py` is not wired to the UI.
- **`reanalyze_with_ai` / CFG / pseudocode** re‑parse the *text* of the disassembly view with naive `split()` instead of keeping a structured instruction list — fragile and lossy.
- ~49 `not implemented / TODO / placeholder / coming soon` markers across `src/`.

**Fix pattern for all of the above:** detect tool availability at startup, disable the corresponding button with a tooltip ("Ghidra not found — install and add to PATH"), and never present a feature that silently errors.

---

## 5. `ultimate_file_protection/` — flag this hard ("no bullshit")

This is a **separate file‑obfuscation/DRM product** bundled into the repo. It is conceptually the *opposite* of a reverse‑engineering tool, and more importantly **several of its headline claims are false**:

- **`quantum_crypto.py` — "CRYSTALS‑Kyber / quantum‑resistant" is fake.** `_kyber_keygen()` and `_kyber_encaps()` literally `return os.urandom(...)`. There is **no Kyber**, no post‑quantum security. It's ECDH‑P521 + AES‑GCM dressed up with random bytes labeled "kyber".
- **`whitebox_crypto.py` — "White‑box AES" is fake and insecure.** It calls standard `AES.MODE_ECB` (ECB leaks plaintext patterns) and builds "obfuscated tables" that are **never used** in `encrypt`/`decrypt`. This is not white‑box crypto.
- `homomorphic_enc.py` at least degrades gracefully when `Pyfhel` is absent (good), but the rest (`anti_re`, `self_destruct`, `polymorphic_engine`, `zk_proofs`, `environmental`, `hardware_security`) are ~50‑line sketches — 621 lines total across 13 files.
- It uses **flat relative imports** (`from quantum_crypto import ...`), so it only runs from inside its own folder and is not integrated with the main app.

**Recommendation:** Remove this subsystem from the reverse‑engineering product, *or* spin it out as a clearly separate, clearly‑labeled "experimental" repo with the false crypto claims corrected. Showing "quantum‑resistant white‑box crypto" that is neither to a company is a credibility risk.

---

## 6. Project hygiene issues

- **`requirements.txt` is duplicated and self‑conflicting** — `capstone>=4.0.2` *and* `capstone>=5.0.0`, `PyQt6` listed twice, two dependency blocks concatenated. Pins like `angr`, `frida`, `torch`, `transformers` are heavy and several **have no wheels for Python 3.14** (the interpreter on this machine). Pick one block, split core vs optional (`requirements-optional.txt`), and target Python 3.11/3.12.
- **No working tests.** `tests/` is empty in git; Downloads has a single 54‑byte `test_root.py`. There is no CI coverage of the bugs in §3.
- **Debug `print("[DEBUG] ...")` everywhere** instead of the logger.
- **Two READMEs/SRS** still say "uses a hardcoded OpenAI API key" (README §"OpenAI API Key") even though the key was removed — stale and alarming to a reviewer. Update the docs.
- Committed artifacts that shouldn't be in VCS: `mitmproxy_capture.log`, `encrypted_files_report.json`, `tools/upx.zip` + extracted UPX, `__pycache__`.
- `.gitignore` is 16 bytes — insufficient.

---

## 7. Prioritized remediation plan

**Phase 0 — Consolidate (½ day)**
1. Make the Downloads copy the source of truth; commit it onto a branch in the git repo. Delete the divergent git‑only versions.
2. Remove committed artifacts; write a proper `.gitignore`.

**Phase 1 — Make it launch and not crash (2–3 days)**
3. Fix §3 bugs #4, #5, #6, #7, #8, #9, #10 (define the display constants, fix the undefined names, move Ghidra off the UI thread, cross‑platform "open file", unify on `multiarch_disassembler`, lazy‑import torch).
4. Clean `requirements.txt`; pin Python 3.11/3.12; separate core vs optional deps. Verify `python main.py` starts on a clean venv on macOS *and* Windows.

**Phase 2 — Make features honest (3–4 days)**
5. Startup capability probe: detect Ghidra/RetDec/Ollama/mitmproxy and disable+tooltip what's absent. No silent error strings in the UI.
6. Keep a structured instruction list in the model; stop re‑parsing the text view for CFG/pseudocode/reanalyze.
7. Implement the real `export_analysis`/`export_iocs`, or remove the menu items.
8. Decide on `ultimate_file_protection`: cut it, or fix the false crypto claims and label it experimental.

**Phase 3 — Demo polish & trust (2–3 days)**
9. Add a smoke‑test suite: load a sample PE/ELF, assert disassembly produces instructions, assert the security‑audit panel returns findings. Wire into CI.
10. Update README/SRS to match reality (remove the hardcoded‑key language, list real prerequisites, state supported platforms/architectures honestly).
11. Replace `print` debugging with the logger; ship a sample binary so the demo is one click.

**Estimated total:** ~8–13 working days to a genuinely demo‑ready, honest "AI‑assisted static analysis workbench."

---

## 8. Honest positioning for the company

Pitch what is **real and differentiated**: a unified PyQt workbench that combines Capstone/LIEF static analysis + multi‑engine decompilation orchestration + live threat‑intel lookups + an AI assist layer, with a plugin system. Do **not** pitch: quantum/white‑box crypto, "full software" one‑click decompilation of arbitrary binaries, or collaboration — those are aspirational. Underclaim, then over‑deliver in the live demo on the core path.
