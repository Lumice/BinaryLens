# BinaryLens (Modernized Fork)

**BinaryLens** is an IDA Pro plugin that accelerates reverse engineering by using large language models to automatically rename subroutines, reconstruct variable names, explain decompiled functions, and summarize binary components.

Compatible with **IDA Pro 8.x and 9.x** (including IDA Pro 9.1 / 9.4 on Windows 10 & 11).

---

## ⚡ Quick Start: 2 Ways to Install

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

## 🚀 Supported Models & Providers

BinaryLens connects to any OpenAI-compatible endpoint, commercial API, or local offline inference engine:

| Provider | Supported Models | Notes |
| :--- | :--- | :--- |
| **Google Gemini** | `gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-1.5-pro` | Fast, high-capacity context window. |
| **DeepSeek** | `deepseek-chat` (V3), `deepseek-reasoner` (R1) | Exceptional coding and low-level reasoning. |
| **OpenAI** | `gpt-4o`, `gpt-4o-mini`, `o3-mini`, `gpt-5` | Industry standard accuracy. |
| **OpenRouter** | `anthropic/claude-3.7-sonnet`, `deepseek/deepseek-r1`, `meta-llama/llama-3.3-70b` | Access any model via unified API key. |
| **Ollama (Offline/Local)** | `qwen2.5-coder:32b`, `deepseek-coder-v2`, `llama3.3` | **100% private**, runs locally on `http://localhost:11434/v1` without an API key. |
| **Custom / LM Studio / vLLM** | Any custom model identifier | Point to your custom Base URL and port. |

---

## 🎯 Features & Usage

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

## 🛠️ Compiling the C++ Plugin (Optional)
If building the native C++ DLL from source:
1. Open `BinaryLens.sln` in Visual Studio 2022.
2. Ensure you have the **IDA 9.x SDK** (`idasdk`) and **OpenSSL 3.x x64** installed.
3. Update `AdditionalIncludeDirectories` and `AdditionalDependencies` in project settings to match your local SDK paths.
4. Build in **Release | x64**.

