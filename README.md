# BinaryLens

[![GitHub stars](https://img.shields.io/github/stars/Lumice/BinaryLens?style=social)](https://github.com/Lumice/BinaryLens)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-8.x%20%7C%209.x-blue)](https://hex-rays.com/ida-pro/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

*Forked and updated from [Berk000x/BinaryLens](https://github.com/Berk000x/BinaryLens).*

BinaryLens is a plugin for IDA Pro that connects to LLMs (large language models) to make reverse engineering faster and easier to read.

![](imgs/idasubroutine.gif?raw=true)

BinaryLens works with IDA Pro 8.x and 9.x on Windows, macOS, and Linux.

---

## Features

### 1. High-Throughput Subroutine Renaming
When IDA disassembles a binary, it assigns generic names like `sub_140001000`. BinaryLens decompiles functions in batches, prompts the model for semantic identification, and renames them to PascalCase names (e.g., `ValidateUserToken`, `DecryptPayload`).
* Menu location: `Edit -> BinaryLens -> Rename all subroutines`
* Contextual Hints: Provide optional target hints (e.g., "network protocol" or "file parser"). A drop-down menu preserves hint history.
* Adaptive Queueing: Prompts are bounded to 45,000 characters. Subroutines that exceed batch boundaries are smoothly carried to the next batch without silent truncation.
* Smart Filtering: Automatically ignores static library runtime code (FLIRT `FUNC_LIB`) and compiler thunk jumps (`FUNC_THUNK`) to conserve tokens and protect known symbols.

### 2. Pseudocode Variable Renaming
Within the Hex-Rays pseudocode view, local variables often have meaningless names like `a1`, `v1`, and `v2`. BinaryLens inspects variable data flows and assigns descriptive names (e.g., `SocketHandle`, `PacketSize`).
* How to use: Right-click inside any pseudocode window and select `BinaryLens: Rename Variables`.

### 3. Function Behavior Explanation
BinaryLens analyzes decompiled C pseudocode and prints a structured summary to the IDA Output window, detailing executive behavior, parameters, return values, and potential security considerations.
* How to use: Right-click inside any pseudocode window and select `BinaryLens: Explain Function`.

### 4. Modeless Progress Dialog with Instant Stop
A dedicated progress dialog provides real-time visibility into active analysis.
* Displays batch numbers, processed subroutines, successful renames, and total elapsed runtime.
* Attaches directly to the IDA main window to prevent intrusive desktop floating.
* Clicking `Stop Analysis` immediately sets an internal cancellation fence, terminates background execution, and preserves all completed database mutations.

---

## Architecture and Safety Hardening

BinaryLens is engineered for strict database integrity and thread safety:

* **Monotonic Run Ownership**: Every analysis session is assigned a monotonic run ID guarded by an internal lock. Stale or cancelled worker threads cannot write to the active database.
* **Symbol Allowlisting**: All proposed renames must exist within the exact batch submitted. Injected or hallucinated addresses returned by models are rejected.
* **Content Hash Verification**: Functions are fingerprinted with a SHA-256 byte hash before prompt submission. If a function is modified concurrently in the database during network transit, the rename is discarded.
* **Main Thread Synchronization**: All Hex-Rays decompilation and database mutation calls are synchronized through `ida_kernwin.execute_sync` under `MFF_WRITE`. All IDA console logging is marshaled via `MFF_FAST`.
* **Pipelined Batch Execution**: Overlaps remote LLM network latency with main-thread decompilation of the subsequent batch, eliminating idle CPU time without increasing concurrent network load.
* **Network Fault Tolerance**: Enforces a 5 MB payload ceiling on model responses and executes automatic retries with exponential backoff on HTTP 429, 5xx, and socket timeouts. Session identifiers are rotated on retries to bypass stalled gateway buffers.
* **Reasoning Trace Segregation**: Separates chain-of-thought reasoning from actual response data. Model reasoning traces are logged diagnostics and never substituted for code modifications.
* **Atomic Configuration**: Configuration files are written to temporary files, flushed, synced via `os.fsync`, and replaced atomically to prevent configuration file corruption.
* **Cross-Version Qt Abstraction**: Resolves UI enums dynamically across PySide6, PyQt6, and PyQt5.

---

## Installation

### Option A: IDA 9.x (HCLI / Plugin Manager)
Install directly from the release package using the Hex-Rays Command Line Interface:
```bash
hcli plugin install BinaryLens-v1.2.0.zip
```

### Option B: Manual Drop-in (IDA 8.x and 9.x)
BinaryLens is a pure IDAPython plugin with zero C++ compilation and no external pip dependencies.
1. Copy `binarylens.py` into your IDA plugins directory:
   * Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
   * Linux / macOS: `~/.idapro/plugins/`
2. Start or restart IDA Pro.
3. Open `Edit -> BinaryLens -> Settings...` to configure your endpoint and model.

---

## Supported Providers

BinaryLens works with any OpenAI-compatible completions endpoint:

* **OpenCode Go & Zen**: `https://opencode.ai/zen/go/v1` (Recommended: `deepseek-v4-flash`)
* **Local Offline Models (Ollama)**: `http://localhost:11434/v1` (no API key required)
* **Local Offline Models (LM Studio)**: `http://localhost:1234/v1` (no API key required)
* **Google Gemini**: `https://generativelanguage.googleapis.com/v1beta/openai`
* **DeepSeek**: `https://api.deepseek.com/v1`
* **OpenAI**: `https://api.openai.com/v1`
* **OpenRouter**: `https://openrouter.ai/api/v1`

---

## Configuration Settings

Access the configuration dialog via `Edit -> BinaryLens -> Settings...`:

* **Preset**: Quick-fills endpoint URLs and recommended models for major providers.
* **Base URL**: The root URL for the OpenAI-compatible completion API.
* **Model Name**: The target model identifier (e.g., `deepseek-v4-flash`, `gemini-2.5-pro`).
* **API Key**: Authentication token for cloud providers (optional for local models).
* **Batch Size**: Number of subroutines processed per prompt (default: `20`; 15–30 recommended).
* **Reasoning Level**: Thinking intensity for reasoning models (`none`, `low`, `medium`, `high`). Setting to `none` is recommended for maximum batch throughput.
* **Max Function Size (KB)**: Skips subroutines exceeding this size threshold to avoid decompiler stalls on unrolled code (default: `12` KB; `0` disables limit).
* **Timeout (Seconds)**: Socket timeout bounded between 10s and 30s (default: `20`s) to fail fast on stalled reverse proxies and retry cleanly.
