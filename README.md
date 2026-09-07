# BinaryLens (Modernized Fork)

[![GitHub stars](https://img.shields.io/github/stars/Lumice/BinaryLens?style=social)](https://github.com/Lumice/BinaryLens)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-8.x%20%7C%209.x-blue)](https://hex-rays.com/ida-pro/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

*Forked and modernized from the original [Berk000x/BinaryLens](https://github.com/Berk000x/BinaryLens).*

**BinaryLens** is an IDA Pro plugin that accelerates reverse engineering by using LLMs to automatically rename subroutines, reconstruct variable names, explain decompiled functions, and summarize binary components.

![](imgs/showcase.gif?raw=true)

Compatible with **IDA Pro 8.x and 9.x** (including IDA Pro 9.1 / 9.4 on Windows 10 & 11).

---

## Quick Start: 2 Ways to Install

### Option 1: Drop-in IDAPython Plugin (Recommended, Zero-Compilation)
No C++ compiler, IDA SDK, or external OpenSSL DLLs required!

1. Copy [`python/binarylens.py`](file:///C:/Users/hue/.gemini/antigravity/scratch/BinaryLens/python/binarylens.py) into your IDA plugins folder:
   - **User plugins folder (Recommended)**: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
   - **System plugins folder**: `%ProgramFiles%\IDA Professional 9.4\plugins\`
2. Restart IDA Pro or open an IDB.
3. Access **Edit → BinaryLens → Settings...** to choose your provider, enter your API key or configure a local Ollama endpoint.

### Option 2: Native C++ Plugin (`BinaryLens.dll`)
1. Place **`libcrypto-3-x64.dll`** and **`libssl-3-x64.dll`** into the IDA root directory (e.g. `%ProgramFiles%/IDA Professional 9.4`).
2. Copy the compiled **`BinaryLens.dll`** into `%ProgramFiles%/IDA Professional 9.4/plugins`.

---

## Model & Provider Support

BinaryLens works with **any model from any provider that supports the standard OpenAI-compatible API format**. There are no hardcoded model restrictions.

You simply configure:
- **API Base URL**: The endpoint of your chosen provider or local server.
- **Model Identifier**: Any model name you wish to invoke (cloud or local).
- **API Key**: Your API key (or leave empty for local inference).

### Common Endpoints

- **Local Inference (Private & Offline)**:
  - **Ollama**: `http://localhost:11434/v1` (no API key required)
  - **LM Studio**: `http://localhost:1234/v1` (no API key required)
  - **vLLM / llama.cpp / LocalAI**: Point to your local endpoint `/v1`
- **Cloud Providers**:
  - **OpenCode Go**: `https://opencode.ai/zen/go/v1` (Default: `deepseek-v4-flash`; also supports `qwen3.8-flash`, `qwen3.7-plus`, `minimax-m3`, `glm-5.3-flash`, `kimi-k3`, `grok-4.6`, `gpt-5.6-luna`, `longcat-2.0`, `mimo-v2.5`)
  - **OpenCode Zen**: `https://opencode.ai/zen/v1`
  - **OpenAI**: `https://api.openai.com/v1`
  - **Google Gemini**: `https://generativelanguage.googleapis.com/v1beta/openai`
  - **DeepSeek**: `https://api.deepseek.com/v1`
  - **OpenRouter**: `https://openrouter.ai/api/v1` (Claude, Llama, Qwen, etc.)
  - Any custom corporate gateway or reverse proxy.

---

## Features & Usage

1. **Rename all subroutines**:
   - Menu: **Edit → BinaryLens → Rename all subroutines**.
   - Automatically decompiles `sub_*` routines, batches them to preserve context while avoiding timeouts, and assigns descriptive PascalCase names (e.g., `sub_140001000` $\rightarrow$ `DecryptAesPayload`).
2. **Rename Variables**:
   - In Hex-Rays Pseudocode view: **Right-click → BinaryLens: Rename Variables**.
   - Semantically renames obscure local variables (`a1`, `v1`, `v2` $\rightarrow$ `socket_fd`, `buffer_len`, `key_schedule`).
3. **Explain Function**:
   - In Hex-Rays Pseudocode view: **Right-click → BinaryLens: Explain Function**.
   - Generates an executive summary, argument breakdown, and security analysis.
4. **Interactive Settings**:
   - Menu: **Edit → BinaryLens → Settings...** (in IDAPython) or **Edit → BinaryLens → Select model** (in C++).

---

## Compiling the C++ Plugin (Optional)
If building the native C++ DLL from source:
1. Open `BinaryLens.sln` in Visual Studio 2022.
2. Ensure you have the **IDA 9.x SDK** (`idasdk`) and **OpenSSL 3.x x64** installed.
3. Update `AdditionalIncludeDirectories` and `AdditionalDependencies` in project settings to match your local SDK paths.
4. Build in **Release | x64**.

