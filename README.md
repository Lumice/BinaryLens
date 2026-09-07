# BinaryLens

[![GitHub stars](https://img.shields.io/github/stars/Lumice/BinaryLens?style=social)](https://github.com/Lumice/BinaryLens)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-8.x%20%7C%209.x-blue)](https://hex-rays.com/ida-pro/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

*Forked and updated from [Berk000x/BinaryLens](https://github.com/Berk000x/BinaryLens).*

BinaryLens is a plugin for IDA Pro that connects to LLMs (large language models) to make reverse engineering faster and easier to read.

![](imgs/showcase.gif?raw=true)

BinaryLens works with IDA Pro 8.x and 9.x on Windows, macOS, and Linux.

---

## Features

### 1. Rename All Subroutines
When IDA disassembles a binary file, it gives unknown functions generic names like `sub_140001000`. BinaryLens decompiles these functions in batches, asks the model what they do, and renames them to descriptive names like `ValidateUserToken` or `CalculateCameraTransform`.

* Menu location: `Edit -> BinaryLens -> Rename all subroutines`
* You can provide an optional target hint (for example, "Unreal Engine 5 tactical shooter") to help the model pick accurate names. A drop-down menu remembers your previous inputs so you can easily reuse them or clear history.

### 2. Rename Variables in a Function
In the Hex-Rays pseudocode view, local variables often have generic names like `a1`, `v1`, and `v2`. BinaryLens reads the function code and renames those variables to names that describe their purpose, like `socket_handle` or `packet_size`.

* How to use: Right-click inside any pseudocode window and select `BinaryLens: Rename Variables`.

### 3. Explain Current Function
BinaryLens reads the decompiled C pseudocode of the active function and prints an explanation in the IDA Output window. The explanation describes the purpose of the function, the function arguments, and potential security issues.

* How to use: Right-click inside any pseudocode window and select `BinaryLens: Explain Function`.

### 4. Progress Window with Instant Stop
When you start a batch analysis, a progress dialog appears.
* It displays the current batch number, the total batches, and how many functions were renamed.
* It stays attached to IDA so it does not float over other applications when you switch windows.
* If you want to halt the process, click the `Stop Analysis` button. The window closes immediately and preserves all renames completed so far.
* You can also click `Edit -> BinaryLens -> Stop analysis` from the menu at any time.

### 5. Reasoning Level Control
Some models, like DeepSeek V4 Flash, spend extra tokens on internal chain-of-thought thinking before they answer. BinaryLens includes a Reasoning Level setting (`none`, `low`, `medium`, `high`).
* Setting the level to `none` is recommended for batch renaming. This mode delivers maximum speed and prevents the model from running out of tokens on large function lists.

---

## Installation (IDAPython Plugin)

You do not need a C++ compiler or external DLL files.

1. Copy `python/binarylens.py` into your IDA plugins directory:
   * Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
   * Linux / macOS: `~/.idapro/plugins/`
2. Start IDA Pro.
3. Open `Edit -> BinaryLens -> Settings...` to choose your provider, enter your API key, and select your model.

---

## Supported Providers

BinaryLens works with any provider that supports the standard OpenAI-compatible format:

* **OpenCode Go & Zen**: `https://opencode.ai/zen/go/v1` (Default model: `deepseek-v4-flash`)
* **Local Offline Models (Ollama)**: `http://localhost:11434/v1` (no API key required)
* **Local Offline Models (LM Studio)**: `http://localhost:1234/v1` (no API key required)
* **Google Gemini**: `https://generativelanguage.googleapis.com/v1beta/openai`
* **DeepSeek**: `https://api.deepseek.com/v1`
* **OpenAI**: `https://api.openai.com/v1`
* **OpenRouter**: `https://openrouter.ai/api/v1`

---

## Configuration Settings

Open `Edit -> BinaryLens -> Settings...` to customize your setup:

* **Preset**: Quick-fills the base URL and recommended model for popular providers.
* **Base URL**: The web address of the completion API endpoint.
* **Model Name**: The model identifier you want to call (such as `deepseek-v4-flash` or `gemini-2.5-pro`).
* **API Key**: Your secret key for cloud providers. Leave this empty for local tools like Ollama or LM Studio.
* **Batch Size**: The number of functions sent in each prompt (default: `40`).
* **Reasoning Level**: The thinking intensity for reasoning models. Keep this at `none` for fast batch renaming.
