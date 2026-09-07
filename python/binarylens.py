"""
BinaryLens for IDA Pro (IDAPython version)
An intelligent IDA Pro plugin that accelerates reverse engineering using LLMs.

Compatible with IDA Pro 8.x and 9.x (Python 3.9 - 3.14).
Works with any OpenAI-compatible API (Ollama, Gemini, DeepSeek, OpenAI, OpenRouter, LM Studio).
No C++ compilation or OpenSSL DLLs required!
"""

import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Dict, List, Optional, Tuple, Any

# IDA Pro modules
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_name

# Qt UI support (Bundled with IDA Pro: PySide6 in IDA 9+, PyQt5 in IDA 7/8)
HAS_QT = False
try:
    from PySide6 import QtWidgets, QtCore, QtGui
    HAS_QT = True
except ImportError:
    try:
        from PyQt5 import QtWidgets, QtCore, QtGui
        HAS_QT = True
    except ImportError:
        try:
            from PyQt6 import QtWidgets, QtCore, QtGui
            HAS_QT = True
        except ImportError:
            try:
                from PySide2 import QtWidgets, QtCore, QtGui
                HAS_QT = True
            except ImportError:
                pass


def post_ida_msg(text: str) -> None:
    """Thread-safe dispatch for IDA console messages."""
    def emit():
        ida_kernwin.msg(text)
        return 1
    ida_kernwin.execute_sync(emit, ida_kernwin.MFF_FAST)


def qt_enum(owner, scope: str, member: str, default: Any = None) -> Any:
    """Seamlessly resolve Qt enums across PyQt5, PyQt6, PySide2, and PySide6."""
    if owner is None:
        return default
    scoped = getattr(owner, scope, None)
    if scoped is not None and hasattr(scoped, member):
        return getattr(scoped, member)
    if hasattr(owner, member):
        return getattr(owner, member)
    return default


def get_func_content_hash(ea: int) -> str:
    """Compute a fast hash of the function byte content to detect stale/concurrent modifications."""
    f = ida_funcs.get_func(ea)
    if not f:
        return ""
    size = f.end_ea - f.start_ea
    if size <= 0 or size > 10 * 1024 * 1024:
        return f"{f.start_ea}_{size}"
    b = ida_bytes.get_bytes(f.start_ea, size)
    if not b:
        return f"{f.start_ea}_{size}"
    import hashlib
    return hashlib.sha256(b).hexdigest()[:16]


# Default configuration
CONFIG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "BinaryLens")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

DEFAULT_CONFIG = {
    "provider": "Gemini",
    "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
    "model": "gemini-2.5-pro",
    "api_key": "",
    "batch_size": 40,
    "max_tokens_per_req": 128000,
    "timeout_sec": 180,
    "reasoning_effort": "none",
    "max_func_size_kb": 12,
    "hint_history": [],
}

ENDPOINT_PRESETS = {
    "Local: Ollama (http://localhost:11434/v1)": "http://localhost:11434/v1",
    "Local: LM Studio (http://localhost:1234/v1)": "http://localhost:1234/v1",
    "Cloud: OpenCode Go (https://opencode.ai/zen/go/v1)": "https://opencode.ai/zen/go/v1",
    "Cloud: OpenCode Zen (https://opencode.ai/zen/v1)": "https://opencode.ai/zen/v1",
    "Cloud: OpenAI (https://api.openai.com/v1)": "https://api.openai.com/v1",
    "Cloud: Google Gemini (https://generativelanguage.googleapis.com/v1beta/openai)": "https://generativelanguage.googleapis.com/v1beta/openai",
    "Cloud: DeepSeek (https://api.deepseek.com/v1)": "https://api.deepseek.com/v1",
    "Cloud: OpenRouter (https://openrouter.ai/api/v1)": "https://openrouter.ai/api/v1",
    "Custom Base URL": "",
}

SUB_REN_SYS_PROMPT = """You are a senior reverse engineering analyst specializing in C decompilation.
You are given a batch of decompiled C functions from an unknown binary.

Your task:
1. Analyze the logic, API calls, strings, and control flow of each function.
2. Infer what each function does and assign a short, precise PascalCase name.
3. Keep names concise (e.g. ParseConfig, DecryptBuffer, ValidateToken, InitSocket).
4. Provide a brief 1-line summary of what the binary or component does.

Return your response strictly as JSON with this exact schema:
{
  "summary": "Brief component/binary summary",
  "renamed_functions": {
    "sub_140001000": "PascalCaseName1",
    "sub_140001200": "PascalCaseName2"
  }
}
Do not include any conversational intro, notes, or extra commentary outside the JSON block.
"""

VAR_REN_SYS_PROMPT = """You are a senior reverse engineering analyst specializing in C decompilation.
You are given a single decompiled C function.

Your task:
1. Understand the function's logic thoroughly.
2. Assign clean, descriptive PascalCase names to its arguments and local variables.
3. Provide a short 1-2 sentence summary of what the function does.

Return your response strictly as JSON with this exact schema:
{
  "summary": "Brief description of the function's behavior",
  "renamed_variables": {
    "a1": "InSocket",
    "v1": "PacketSize",
    "v2": "DecryptBuffer"
  }
}
Do not include any conversational text or commentary outside the JSON block.
"""

EXPLAIN_SYS_PROMPT = """You are an expert reverse engineer and security researcher.
Analyze the following decompiled C function from IDA Pro.
Explain:
1. Executive Summary (High-level purpose)
2. Arguments and Return Value
3. Step-by-Step Logic
4. Potential Security or Reversing Insights (crypto, network, file IO, suspicious patterns)

Be concise, technical, and accurate.
"""

def load_config() -> dict:
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                config = DEFAULT_CONFIG.copy()
                config.update(data)
                if not isinstance(config.get("hint_history"), list):
                    config["hint_history"] = []
                return config
    except Exception as e:
        post_ida_msg(f"[BinaryLens] Warning: Failed to load config: {e}\n")
    return DEFAULT_CONFIG.copy()

def save_config(config: dict) -> bool:
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        tmp_file = CONFIG_FILE + f".tmp.{os.getpid()}"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file, CONFIG_FILE)
        return True
    except Exception as e:
        post_ida_msg(f"[BinaryLens] Error saving config: {e}\n")
        return False

def add_hint_to_history(config: dict, hint: str) -> None:
    """Add a hint string to recent hint history, deduplicating and moving to top."""
    hint = hint.strip()
    if not hint:
        return
    history = config.get("hint_history", [])
    if not isinstance(history, list):
        history = []
    history = [h for h in history if h != hint]
    history.insert(0, hint)
    config["hint_history"] = history[:25]
    save_config(config)

def sanitize_identifier(name: str) -> str:
    """Ensure a string is a valid C/IDA identifier."""
    if not name:
        return ""
    name = name.strip().strip('"').strip("'").strip('`')
    cleaned = re.sub(r'[^a-zA-Z0-9_]+', '_', name).strip('_')
    if not cleaned:
        return ""
    if cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned

def truncate_pseudocode(lines: List[str], max_lines: int = 150) -> str:
    """Keep the start and end of large functions to preserve context without blowing token limits."""
    if len(lines) <= max_lines:
        return "\n".join(lines)
    head_count = int(max_lines * 0.8)
    tail_count = max_lines - head_count
    head = lines[:head_count]
    tail = lines[-tail_count:]
    omitted = len(lines) - max_lines
    return "\n".join(head) + f"\n\n// ... [{omitted} lines truncated for length] ...\n\n" + "\n".join(tail)

def extract_balanced_json(text: str) -> Optional[dict]:
    """Finds the first balanced { ... } JSON object in text, handling strings and escape sequences."""
    start = text.find('{')
    while start != -1:
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            c = text[i]
            if escape:
                escape = False
                continue
            if c == '\\':
                escape = True
                continue
            if c == '"':
                in_string = not in_string
                continue
            if not in_string:
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        candidate = text[start:i+1]
                        try:
                            res = json.loads(candidate)
                            if isinstance(res, dict):
                                return res
                        except Exception:
                            break
        start = text.find('{', start + 1)
    return None

def parse_model_response(raw_text: str) -> Tuple[str, Dict[str, str]]:
    """
    Extracts summary and mapping (functions or variables) from JSON or INI format.
    Handles code fences, markdown wrapping, and malformed responses.
    """
    summary = ""
    mapping: Dict[str, str] = {}

    text = raw_text.strip()

    # 1. Try extracting JSON via markdown code fences first
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    data = None
    if fence_match:
        try:
            parsed = json.loads(fence_match.group(1))
            if isinstance(parsed, dict):
                data = parsed
        except Exception:
            pass

    # 2. Try balanced brace extraction if fence wasn't present or failed
    if not data:
        data = extract_balanced_json(text)

    # 3. Fallback to greedy regex if balanced didn't succeed
    if not data:
        json_match = re.search(r'\{.*\}', text, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group(0))
                if isinstance(parsed, dict):
                    data = parsed
            except Exception:
                pass

    if data:
        cand_summary = data.get("summary", "")
        summary = cand_summary.strip() if isinstance(cand_summary, str) else ""
        # Function mappings
        funcs = data.get("renamed_functions") or data.get("RenamedFunctions") or data.get("functions")
        if isinstance(funcs, dict):
            for k, v in funcs.items():
                if isinstance(k, str) and isinstance(v, str):
                    san = sanitize_identifier(v)
                    if san:
                        mapping[k.strip()] = san

        # Variable mappings
        vars_dict = data.get("renamed_variables") or data.get("RenamedLocals") or data.get("variables")
        if isinstance(vars_dict, dict):
            for k, v in vars_dict.items():
                if isinstance(k, str) and isinstance(v, str):
                    san = sanitize_identifier(v)
                    if san:
                        mapping[k.strip()] = san

        if mapping:
            return summary, mapping

    # 2. Fallback: Parse INI style [RenamedFunctions] or [RenamedLocals]
    cur_section = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("#") or line.startswith("```"):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur_section = line[1:-1].strip()
            continue
        if "=" in line:
            parts = line.split("=", 1)
            key = parts[0].strip()
            val = parts[1].strip()
            if cur_section in ("BinaryInfo", "FunctionInfo") and key.lower() == "summary":
                summary = val
            elif cur_section in ("RenamedFunctions", "RenamedLocals"):
                mapping[key] = sanitize_identifier(val)
            elif not cur_section and (key.startswith("sub_") or key.startswith("v") or key.startswith("a")):
                mapping[key] = sanitize_identifier(val)

    return summary, mapping

def call_llm(
    system_prompt: str,
    user_prompt: str,
    config: dict,
    on_log=None,
    raise_errors: bool = False,
    cancel_check=None
) -> Optional[str]:
    base_url = config.get("base_url", "").strip().rstrip("/")
    if not base_url:
        if on_log:
            on_log("[BinaryLens] Error: Base URL is empty. Configure it in Settings.\n")
        return None

    endpoint = base_url if base_url.endswith("/chat/completions") else f"{base_url}/chat/completions"
    model = config.get("model", "deepseek-v4-flash")
    api_key = config.get("api_key", "").strip()
    timeout = config.get("timeout_sec", 180)

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.2
    }

    # DeepSeek output token bump
    if "deepseek" in model.lower():
        payload["max_tokens"] = 8192

    # BL-011: Omit reasoning_effort when empty, "none", or "default"
    reasoning_effort = config.get("reasoning_effort", "none")
    if reasoning_effort and reasoning_effort not in ("", "none", "default"):
        payload["reasoning_effort"] = reasoning_effort

    body_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(endpoint, data=body_bytes, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) BinaryLens/2.0")
    if "opencode" in endpoint.lower():
        session_id = getattr(call_llm, "_session_id", None)
        if not session_id:
            session_id = f"bl_{uuid.uuid4().hex[:16]}"
            setattr(call_llm, "_session_id", session_id)
        req.add_header("x-opencode-session", session_id)
        req.add_header("x-opencode-client", "binarylens")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")

    ctx = ssl.create_default_context()
    MAX_RETRIES = 2
    MAX_RESP_BYTES = 5 * 1024 * 1024  # 5 MB ceiling (BL-011)

    for attempt in range(MAX_RETRIES + 1):
        if cancel_check and cancel_check():
            return None

        if on_log and attempt == 0:
            on_log(f"[BinaryLens] Dispatching request to {endpoint} (Model: {model})...\n")

        t0 = time.time()
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                elapsed = time.time() - t0
                resp_bytes = resp.read(MAX_RESP_BYTES)
                resp_body = resp_bytes.decode("utf-8", errors="replace")
                data = json.loads(resp_body)
                choices = data.get("choices")
                if not isinstance(choices, list) or not choices:
                    if on_log:
                        on_log(f"[BinaryLens] Warning: Provider returned empty choices array ({elapsed:.1f}s).\n")
                    return None
                first_choice = choices[0]
                if not isinstance(first_choice, dict):
                    return None
                msg = first_choice.get("message", {})
                if not isinstance(msg, dict):
                    return None
                # BL-009: Strict content requirement - never fall back to reasoning_content!
                content = msg.get("content")
                finish_reason = first_choice.get("finish_reason")

                if not isinstance(content, str) or not content.strip():
                    if on_log:
                        on_log(f"[BinaryLens] Warning: Empty content returned from model ({elapsed:.1f}s, finish_reason: {finish_reason}).\n")
                    return None
                if on_log:
                    on_log(f"[BinaryLens] Response received in {elapsed:.1f}s.\n")
                return content.strip()

        except urllib.error.HTTPError as e:
            elapsed = time.time() - t0
            err_msg = e.read(64 * 1024).decode("utf-8", errors="ignore")
            try:
                err_json = json.loads(err_msg)
                if "error" in err_json:
                    err_val = err_json["error"]
                    if isinstance(err_val, dict) and "message" in err_val:
                        err_msg = err_val["message"]
                    elif isinstance(err_val, str):
                        err_msg = err_val
            except Exception:
                pass

            # Retry on transient HTTP errors (429, 500, 502, 503, 504)
            if e.code in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES:
                retry_delay = 2.0 * (attempt + 1)
                retry_after = e.headers.get("Retry-After") if hasattr(e, "headers") else None
                if retry_after:
                    try:
                        retry_delay = max(retry_delay, min(float(retry_after), 30.0))
                    except (ValueError, TypeError):
                        pass
                if on_log:
                    on_log(f"[BinaryLens] HTTP {e.code} ({err_msg}). Retrying in {retry_delay:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})...\n")
                time.sleep(retry_delay)
                continue

            if on_log:
                on_log(f"[BinaryLens] HTTP Error {e.code}: {err_msg}\n")
            if raise_errors:
                raise RuntimeError(f"HTTP {e.code}: {err_msg}")
            return None

        except (urllib.error.URLError, TimeoutError, OSError) as e:
            elapsed = time.time() - t0
            if attempt < MAX_RETRIES:
                retry_delay = 2.0 * (attempt + 1)
                if on_log:
                    on_log(f"[BinaryLens] Network error ({e}). Retrying in {retry_delay:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})...\n")
                time.sleep(retry_delay)
                continue
            if on_log:
                on_log(f"[BinaryLens] Request failed: {e}\n")
            if raise_errors:
                raise
            return None
        except Exception as e:
            if on_log:
                on_log(f"[BinaryLens] Unexpected error: {e}\n")
            if raise_errors:
                raise
            return None

    return None


if HAS_QT:
    class QtSettingsDialog(QtWidgets.QDialog):
        """Native Qt configuration dialog for BinaryLens."""
        def __init__(self, config: dict, parent=None):
            super().__init__(parent)
            self.config = config
            self.setWindowTitle("BinaryLens Configuration")
            self.setMinimumWidth(560)

            main_layout = QtWidgets.QVBoxLayout(self)
            main_layout.setSpacing(12)

            title_label = QtWidgets.QLabel("<b>BinaryLens Configuration</b>")
            subtitle_label = QtWidgets.QLabel("Configure your LLM provider, OpenAI-compatible Base URL, Model Name, and API Key.")
            subtitle_label.setStyleSheet("color: gray; margin-bottom: 6px;")
            main_layout.addWidget(title_label)
            main_layout.addWidget(subtitle_label)

            form_layout = QtWidgets.QFormLayout()
            growth = qt_enum(QtWidgets.QFormLayout, "FieldGrowthPolicy", "ExpandingFieldsGrow")
            if growth is not None:
                form_layout.setFieldGrowthPolicy(growth)

            # Presets dropdown
            self.preset_combo = QtWidgets.QComboBox()
            self.presets_list = list(ENDPOINT_PRESETS.keys())
            self.preset_combo.addItems(self.presets_list)
            cur_preset = config.get("preset", "")
            if cur_preset in self.presets_list:
                self.preset_combo.setCurrentIndex(self.presets_list.index(cur_preset))
            self.preset_combo.currentIndexChanged.connect(self._on_preset_changed)
            form_layout.addRow("Preset:", self.preset_combo)

            # Base URL
            self.base_url_edit = QtWidgets.QLineEdit()
            self.base_url_edit.setText(config.get("base_url", ""))
            self.base_url_edit.setPlaceholderText("http://localhost:11434/v1")
            form_layout.addRow("Base URL:", self.base_url_edit)

            # Model Name
            self.model_edit = QtWidgets.QLineEdit()
            self.model_edit.setText(config.get("model", ""))
            self.model_edit.setPlaceholderText("e.g. gemini-2.5-pro, deepseek-chat, llama3")
            form_layout.addRow("Model Name:", self.model_edit)

            # API Key row with show/hide toggle
            self._echo_pwd = qt_enum(QtWidgets.QLineEdit, "EchoMode", "Password", 2)
            self._echo_norm = qt_enum(QtWidgets.QLineEdit, "EchoMode", "Normal", 0)

            self.api_key_edit = QtWidgets.QLineEdit()
            self.api_key_edit.setText(config.get("api_key", ""))
            self.api_key_edit.setEchoMode(self._echo_pwd)
            self.api_key_edit.setPlaceholderText("Leave empty for Ollama / LM Studio")

            key_container = QtWidgets.QWidget()
            key_layout = QtWidgets.QHBoxLayout(key_container)
            key_layout.setContentsMargins(0, 0, 0, 0)
            key_layout.addWidget(self.api_key_edit)
            self.toggle_key_cb = QtWidgets.QCheckBox("Show")
            self.toggle_key_cb.toggled.connect(self._toggle_key_visibility)
            key_layout.addWidget(self.toggle_key_cb)
            form_layout.addRow("API Key:", key_container)

            # Batch Size
            self.batch_size_spin = QtWidgets.QSpinBox()
            self.batch_size_spin.setRange(1, 200)
            self.batch_size_spin.setValue(int(config.get("batch_size", 40)))
            self.batch_size_spin.setToolTip("Number of subroutines analyzed per prompt batch.")
            form_layout.addRow("Batch Size:", self.batch_size_spin)

            # Reasoning Level
            self.reasoning_combo = QtWidgets.QComboBox()
            self.reasoning_options = ["none", "low", "medium", "high", "default"]
            self.reasoning_combo.addItems(self.reasoning_options)
            cur_effort = config.get("reasoning_effort", "none")
            if cur_effort in self.reasoning_options:
                self.reasoning_combo.setCurrentIndex(self.reasoning_options.index(cur_effort))
            self.reasoning_combo.setToolTip("Reasoning/thinking effort for models that support it. 'none' or 'low' is recommended for batch analysis.")
            form_layout.addRow("Reasoning Level:", self.reasoning_combo)

            # Max Function Size (KB)
            self.max_func_size_spin = QtWidgets.QSpinBox()
            self.max_func_size_spin.setRange(0, 200)
            self.max_func_size_spin.setValue(int(config.get("max_func_size_kb", 12)))
            self.max_func_size_spin.setToolTip("Skip functions larger than this size in batch mode to avoid freezing Hex-Rays on unrolled code (e.g. 12 KB). Set to 0 to disable limit.")
            form_layout.addRow("Max Function Size (KB):", self.max_func_size_spin)

            main_layout.addLayout(form_layout)

            # Test connection row
            test_container = QtWidgets.QWidget()
            test_layout = QtWidgets.QHBoxLayout(test_container)
            test_layout.setContentsMargins(0, 4, 0, 4)
            self.test_btn = QtWidgets.QPushButton("Test Connection")
            self.test_btn.clicked.connect(self._test_connection)
            self.test_status = QtWidgets.QLabel("")
            test_layout.addWidget(self.test_btn)
            test_layout.addWidget(self.test_status)
            test_layout.addStretch()
            main_layout.addWidget(test_container)

            # Dialog buttons (Save / Cancel)
            btn_layout = QtWidgets.QHBoxLayout()
            btn_layout.addStretch()
            self.save_btn = QtWidgets.QPushButton("Save")
            self.save_btn.setDefault(True)
            self.save_btn.clicked.connect(self.accept)
            self.cancel_btn = QtWidgets.QPushButton("Cancel")
            self.cancel_btn.clicked.connect(self.reject)
            btn_layout.addWidget(self.save_btn)
            btn_layout.addWidget(self.cancel_btn)
            main_layout.addLayout(btn_layout)

        def _toggle_key_visibility(self, checked):
            if checked:
                self.api_key_edit.setEchoMode(self._echo_norm)
            else:
                self.api_key_edit.setEchoMode(self._echo_pwd)

        def _on_preset_changed(self, idx):
            if 0 <= idx < len(self.presets_list):
                p_name = self.presets_list[idx]
                url = ENDPOINT_PRESETS.get(p_name, "")
                if url:
                    self.base_url_edit.setText(url)
                cur_m = self.model_edit.text().strip()
                known_defaults = {"", "llama3", "gemini-2.5-pro", "gemini-2.5-flash", "deepseek-chat", "deepseek-v4-pro", "deepseek-v4-flash", "gpt-4o-mini", "local-model"}
                if cur_m in known_defaults:
                    if "OpenCode" in p_name:
                        self.model_edit.setText("deepseek-v4-flash")
                    elif "Gemini" in p_name:
                        self.model_edit.setText("gemini-2.5-pro")
                    elif "DeepSeek" in p_name:
                        self.model_edit.setText("deepseek-chat")
                    elif "OpenAI" in p_name:
                        self.model_edit.setText("gpt-4o-mini")
                    elif "Ollama" in p_name:
                        self.model_edit.setText("llama3")
                    elif "LM Studio" in p_name:
                        self.model_edit.setText("local-model")

        def _test_connection(self):
            base_url = self.base_url_edit.text().strip()
            api_key = self.api_key_edit.text().strip()
            model = self.model_edit.text().strip()

            if not base_url:
                self.test_status.setStyleSheet("color: #dc3545;")
                self.test_status.setText("Base URL cannot be empty.")
                return

            self.test_status.setStyleSheet("color: #0d6efd;")
            self.test_status.setText("Testing connection...")
            self.test_btn.setEnabled(False)

            result = {"done": False, "ok": False, "err": ""}

            def do_test():
                try:
                    cfg = {
                        "base_url": base_url,
                        "api_key": api_key,
                        "model": model,
                        "timeout_sec": 15
                    }
                    resp = call_llm(
                        system_prompt="You are a helpful assistant.",
                        user_prompt="Hello",
                        config=cfg,
                        raise_errors=True
                    )
                    if resp is not None:
                        result["ok"] = True
                    else:
                        result["err"] = "Empty response received."
                except Exception as ex:
                    result["err"] = str(ex)
                finally:
                    result["done"] = True

            threading.Thread(target=do_test, daemon=True).start()

            # Poll on main thread to guarantee UI update in PySide6/PyQt5
            poll_timer = QtCore.QTimer(self)
            def check_poll():
                if result["done"]:
                    poll_timer.stop()
                    self.test_btn.setEnabled(True)
                    if result["ok"]:
                        self.test_status.setStyleSheet("color: #198754; font-weight: bold;")
                        self.test_status.setText("Connected successfully!")
                    else:
                        self.test_status.setStyleSheet("color: #dc3545;")
                        err_text = result["err"] or "Request failed."
                        self.test_status.setText(f"Failed: {err_text[:70]}")

            poll_timer.timeout.connect(check_poll)
            poll_timer.start(100)

        def get_values(self):
            return {
                "preset": self.preset_combo.currentText(),
                "base_url": self.base_url_edit.text().strip(),
                "model": self.model_edit.text().strip(),
                "api_key": self.api_key_edit.text().strip(),
                "batch_size": self.batch_size_spin.value(),
                "reasoning_effort": self.reasoning_combo.currentText(),
                "max_func_size_kb": self.max_func_size_spin.value(),
            }


if HAS_QT:
    class BinaryLensProgressDialog(QtWidgets.QDialog):
        """Progress dialog with real-time status and STOP button."""
        def __init__(self, total_batches: int, on_stop_cb, parent=None):
            super().__init__(parent)
            self.on_stop_cb = on_stop_cb
            self._programmatic_close = False
            self.setWindowTitle("BinaryLens Progress")
            self.resize(380, 140)

            layout = QtWidgets.QVBoxLayout(self)

            self.status_lbl = QtWidgets.QLabel("Initializing analysis...")
            self.status_lbl.setStyleSheet("font-weight: bold; font-size: 10pt;")
            layout.addWidget(self.status_lbl)

            self.pbar = QtWidgets.QProgressBar()
            self.pbar.setRange(0, total_batches)
            self.pbar.setValue(0)
            self.pbar.setTextVisible(True)
            layout.addWidget(self.pbar)

            self.stats_lbl = QtWidgets.QLabel("Renamed: 0 functions")
            layout.addWidget(self.stats_lbl)

            btn_layout = QtWidgets.QHBoxLayout()
            btn_layout.addStretch()

            self.stop_btn = QtWidgets.QPushButton("Stop Analysis")
            cursor_shape = qt_enum(QtCore.Qt, "CursorShape", "PointingHandCursor", getattr(QtCore.Qt, "ArrowCursor", None) if hasattr(QtCore, "Qt") else None)
            if cursor_shape:
                self.stop_btn.setCursor(cursor_shape)
            self.stop_btn.setStyleSheet("""
                QPushButton {
                    padding: 6px 18px;
                    font-weight: bold;
                    border: 1px solid #d9534f;
                    border-radius: 4px;
                    background-color: transparent;
                    color: #d9534f;
                }
                QPushButton:hover {
                    background-color: #d9534f;
                    color: #ffffff;
                    border: 1px solid #c9302c;
                }
                QPushButton:pressed {
                    background-color: #ac2925;
                    color: #ffffff;
                    border: 1px solid #ac2925;
                }
            """)
            self.stop_btn.clicked.connect(self._handle_stop)
            btn_layout.addWidget(self.stop_btn)

            layout.addLayout(btn_layout)

        def _handle_stop(self):
            if self.on_stop_cb:
                self.on_stop_cb()
            self.close()

        def update_progress(self, batch_num: int, total_batches: int, renamed_count: int, elapsed_sec: Optional[float] = None):
            self.pbar.setValue(batch_num)
            self.status_lbl.setText(f"Batch {batch_num} of {total_batches}")
            if elapsed_sec is not None:
                mins = int(elapsed_sec // 60)
                secs = int(elapsed_sec % 60)
                if mins > 0:
                    time_txt = f"{mins}m {secs:02d}s"
                else:
                    time_txt = f"{secs}s"
                self.stats_lbl.setText(f"Renamed: {renamed_count} functions | Elapsed: {time_txt}")
            else:
                self.stats_lbl.setText(f"Renamed: {renamed_count} functions")

        def mark_finished(self, total_renamed: int, aborted: bool = False):
            self._programmatic_close = True
            self.close()

        def closeEvent(self, event):
            if not self._programmatic_close and self.on_stop_cb:
                self.on_stop_cb()
            event.accept()


    class QtTargetHintDialog(QtWidgets.QDialog):
        """Dialog with a history dropdown for target hints before batch renaming."""
        def __init__(self, config: dict, parent=None):
            super().__init__(parent)
            self.config = config
            self.setWindowTitle("BinaryLens - Subroutine Analysis")
            self.setMinimumWidth(540)

            layout = QtWidgets.QVBoxLayout(self)
            layout.setSpacing(12)

            title_label = QtWidgets.QLabel("<b>Target Hint & Context</b>")
            title_label.setStyleSheet("font-size: 11pt;")
            subtitle_label = QtWidgets.QLabel(
                "Provide optional background info or domain hints to guide the LLM.\n"
                "Select a previous input from the dropdown or type a new one."
            )
            subtitle_label.setStyleSheet("color: gray; margin-bottom: 4px;")
            layout.addWidget(title_label)
            layout.addWidget(subtitle_label)

            form_layout = QtWidgets.QFormLayout()
            self.combo = QtWidgets.QComboBox()
            self.combo.setEditable(True)
            no_insert = qt_enum(QtWidgets.QComboBox, "InsertPolicy", "NoInsert", 0)
            self.combo.setInsertPolicy(no_insert)

            history = self.config.get("hint_history", [])
            if isinstance(history, list):
                for item in history:
                    if isinstance(item, str) and item.strip():
                        self.combo.addItem(item.strip())

            line_edit = self.combo.lineEdit()
            if line_edit:
                line_edit.setPlaceholderText("(Optional) Type or select background context / domain hints...")
                line_edit.returnPressed.connect(self.accept)

            if self.combo.count() > 0:
                self.combo.setCurrentIndex(0)
                if line_edit:
                    line_edit.selectAll()
            else:
                self.combo.setCurrentIndex(-1)
                if line_edit:
                    line_edit.clear()

            combo_container = QtWidgets.QWidget()
            combo_row = QtWidgets.QHBoxLayout(combo_container)
            combo_row.setContentsMargins(0, 0, 0, 0)
            combo_row.addWidget(self.combo, 1)

            self.clear_btn = QtWidgets.QPushButton("Clear History")
            self.clear_btn.setToolTip("Clear saved hint history")
            self.clear_btn.clicked.connect(self._clear_history)
            combo_row.addWidget(self.clear_btn)

            form_layout.addRow("Target Hint:", combo_container)
            layout.addLayout(form_layout)

            btn_layout = QtWidgets.QHBoxLayout()
            btn_layout.addStretch()

            self.start_btn = QtWidgets.QPushButton("Start Analysis")
            self.start_btn.setDefault(True)
            self.start_btn.clicked.connect(self.accept)

            self.cancel_btn = QtWidgets.QPushButton("Cancel")
            self.cancel_btn.clicked.connect(self.reject)

            btn_layout.addWidget(self.start_btn)
            btn_layout.addWidget(self.cancel_btn)
            layout.addLayout(btn_layout)

        def _clear_history(self):
            self.combo.clear()
            self.config["hint_history"] = []
            save_config(self.config)
            line_edit = self.combo.lineEdit()
            if line_edit:
                line_edit.clear()
                line_edit.setPlaceholderText("(Optional) Type or select background context / domain hints...")

        def get_hint(self) -> str:
            return self.combo.currentText().strip()


class IdaFormSettingsDialog(ida_kernwin.Form):
    """Fallback configuration dialog using native IDA Form."""
    def __init__(self, config: dict):
        self.config = config
        presets_list = list(ENDPOINT_PRESETS.keys())
        current_p_idx = 0
        if config.get("preset") in presets_list:
            current_p_idx = presets_list.index(config["preset"])

        ida_kernwin.Form.__init__(
            self,
            r"""STARTITEM {id:id_preset}
BUTTON YES Save
BUTTON CANCEL Cancel
BinaryLens Configuration

{FormChangeCb}
<#Quick-fill Base URL preset#Preset    :{id_preset}>
<#OpenAI-compatible Base URL#Base URL  :{id_base_url}>
<#Any model identifier#Model Name:{id_model}>
<#API Key (Leave empty for Ollama / LM Studio)#API Key   :{id_api_key}>
<#Subroutines to send per batch request#Batch Size:{id_batch_size}>
""",
            {
                "FormChangeCb": ida_kernwin.Form.FormChangeCb(self.OnFormChange),
                "id_preset": ida_kernwin.Form.DropdownListControl(
                    items=presets_list,
                    readonly=True,
                    selval=current_p_idx
                ),
                "id_base_url": ida_kernwin.Form.StringInput(value=config.get("base_url", ""), width=1024, swidth=50),
                "id_model": ida_kernwin.Form.StringInput(value=config.get("model", ""), width=1024, swidth=50),
                "id_api_key": ida_kernwin.Form.StringInput(value=config.get("api_key", ""), width=1024, swidth=50),
                "id_batch_size": ida_kernwin.Form.NumericInput(value=int(config.get("batch_size", 40)), tp=ida_kernwin.Form.FT_DEC, width=10, swidth=10),
            }
        )

    def OnFormChange(self, fid):
        if fid == self.id_preset.id:
            sel_idx = self.GetControlValue(self.id_preset)
            presets_list = list(ENDPOINT_PRESETS.keys())
            if sel_idx is not None and 0 <= sel_idx < len(presets_list):
                p_name = presets_list[sel_idx]
                url = ENDPOINT_PRESETS.get(p_name, "")
                if url:
                    self.SetControlValue(self.id_base_url, url)
        return 1


class BinaryLensPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "BinaryLens: AI-Powered Binary Auto-Analysis"
    help = "Fast semantic binary analysis using LLMs"
    wanted_name = "BinaryLens"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self.config = load_config()
        self._run_lock = threading.Lock()
        self._run_id = 0
        self._cancel = threading.Event()
        self.worker_thread: Optional[threading.Thread] = None
        self.is_running = False
        self.progress_dialog = None

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            post_ida_msg("[BinaryLens] Hex-Rays decompiler not detected. Plugin disabled.\n")
            return ida_idaapi.PLUGIN_SKIP

        self._register_actions()
        post_ida_msg("[BinaryLens] Loaded successfully. (Edit -> BinaryLens)\n")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.show_settings()

    def term(self):
        self.stop_analysis()
        self._unregister_actions()

    def _register_actions(self):
        self._unregister_actions()
        # Action 1: Rename Subroutines
        rename_subs_desc = ida_kernwin.action_desc_t(
            "binarylens:rename_subs",
            "Rename all subroutines",
            _ActionHandler(self.rename_all_subs),
            "",
            "Rename unknown subroutines using LLM",
            -1
        )
        ida_kernwin.register_action(rename_subs_desc)
        ida_kernwin.attach_action_to_menu("Edit/BinaryLens/", "binarylens:rename_subs", ida_kernwin.SETMENU_APP)

        # Action 2: Stop Analysis
        stop_analysis_desc = ida_kernwin.action_desc_t(
            "binarylens:stop_analysis",
            "Stop analysis",
            _ActionHandler(self.stop_analysis),
            "",
            "Stop ongoing BinaryLens subroutine analysis",
            -1
        )
        ida_kernwin.register_action(stop_analysis_desc)
        ida_kernwin.attach_action_to_menu("Edit/BinaryLens/", "binarylens:stop_analysis", ida_kernwin.SETMENU_APP)

        # Action 3: Settings
        settings_desc = ida_kernwin.action_desc_t(
            "binarylens:settings",
            "Settings...",
            _ActionHandler(self.show_settings),
            "",
            "Configure BinaryLens LLM model and endpoints",
            -1
        )
        ida_kernwin.register_action(settings_desc)
        ida_kernwin.attach_action_to_menu("Edit/BinaryLens/", "binarylens:settings", ida_kernwin.SETMENU_APP)

        # Action 4: Rename Variables (Context Menu)
        rename_vars_desc = ida_kernwin.action_desc_t(
            "binarylens:rename_vars",
            "BinaryLens: Rename Variables",
            _ActionHandler(self.rename_current_function_vars),
            "",
            "Rename local variables in current function using LLM",
            -1
        )
        ida_kernwin.register_action(rename_vars_desc)

        # Action 5: Explain Function
        explain_desc = ida_kernwin.action_desc_t(
            "binarylens:explain_func",
            "BinaryLens: Explain Function",
            _ActionHandler(self.explain_current_function),
            "",
            "Explain current function behavior with LLM",
            -1
        )
        ida_kernwin.register_action(explain_desc)

        # UI Hook for Pseudocode popup
        self.ui_hooks = _UIHooks(self)
        self.ui_hooks.hook()

    def _unregister_actions(self):
        if hasattr(self, "ui_hooks") and self.ui_hooks:
            try:
                self.ui_hooks.unhook()
            except Exception:
                pass
            self.ui_hooks = None
        ida_kernwin.unregister_action("binarylens:rename_subs")
        ida_kernwin.unregister_action("binarylens:stop_analysis")
        ida_kernwin.unregister_action("binarylens:settings")
        ida_kernwin.unregister_action("binarylens:rename_vars")
        ida_kernwin.unregister_action("binarylens:explain_func")

    def stop_analysis(self):
        with self._run_lock:
            if not self.is_running:
                post_ida_msg("[BinaryLens] No analysis is currently running.\n")
                return
            self._cancel.set()
            self._run_id += 1
            self.is_running = False
        if getattr(self, "progress_dialog", None):
            try:
                self.progress_dialog.mark_finished(0, aborted=True)
                self.progress_dialog = None
            except Exception:
                pass
        post_ida_msg("[BinaryLens] Stop requested. Analysis halted and pending mutations fenced.\n")

    def show_settings(self):
        if HAS_QT:
            try:
                parent = None
                try:
                    parent = QtWidgets.QApplication.activeWindow()
                except Exception:
                    pass
                dialog = QtSettingsDialog(self.config, parent=parent)
                res = dialog.exec() if hasattr(dialog, "exec") else dialog.exec_()
                accepted_code = qt_enum(QtWidgets.QDialog, "DialogCode", "Accepted", 1)
                if res == 1 or res == accepted_code:
                    vals = dialog.get_values()
                    self.config.update(vals)
                    save_config(self.config)
                    ida_kernwin.info(f"BinaryLens settings saved.\nModel: {self.config['model']}\nBase URL: {self.config['base_url']}")
                return
            except Exception as e:
                post_ida_msg(f"[BinaryLens] Qt dialog error, falling back to IDA form: {e}\n")

        # Fallback to ida_kernwin.Form
        dialog = IdaFormSettingsDialog(self.config)
        dialog.Compile()
        ok = dialog.Execute()
        if ok == 1:
            presets_list = list(ENDPOINT_PRESETS.keys())
            sel_idx = dialog.id_preset.value
            self.config["preset"] = presets_list[sel_idx] if 0 <= sel_idx < len(presets_list) else "Custom"
            self.config["base_url"] = dialog.id_base_url.value.strip()
            self.config["model"] = dialog.id_model.value.strip()
            self.config["api_key"] = dialog.id_api_key.value.strip()
            self.config["batch_size"] = max(1, int(dialog.id_batch_size.value))
            save_config(self.config)
            ida_kernwin.info(f"BinaryLens settings saved.\nModel: {self.config['model']}\nBase URL: {self.config['base_url']}")
        dialog.Free()

    def rename_all_subs(self):
        with self._run_lock:
            if self.is_running:
                if HAS_QT:
                    btn_yes = qt_enum(QtWidgets.QMessageBox, "StandardButton", "Yes", 0x4000)
                    btn_no = qt_enum(QtWidgets.QMessageBox, "StandardButton", "No", 0x10000)
                    res = QtWidgets.QMessageBox.question(
                        None,
                        "BinaryLens",
                        "Subroutine analysis is currently in progress.\nDo you want to stop it?",
                        btn_yes | btn_no,
                        btn_no
                    )
                    if res == btn_yes:
                        self.stop_analysis()
                else:
                    res = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "BinaryLens analysis is already running. Do you want to stop it?")
                    if res == ida_kernwin.ASKBTN_YES:
                        self.stop_analysis()
                return

        user_hint = ""
        if HAS_QT:
            try:
                parent = None
                try:
                    parent = QtWidgets.QApplication.activeWindow()
                except Exception:
                    pass
                dialog = QtTargetHintDialog(self.config, parent=parent)
                res = dialog.exec() if hasattr(dialog, "exec") else dialog.exec_()
                accepted_code = qt_enum(QtWidgets.QDialog, "DialogCode", "Accepted", 1)
                if res != 1 and res != accepted_code:
                    return
                user_hint = dialog.get_hint()
                if user_hint:
                    add_hint_to_history(self.config, user_hint)
            except Exception as e:
                post_ida_msg(f"[BinaryLens] Hint dialog error, falling back: {e}\n")
                user_hint = ida_kernwin.ask_str("", -1, "(Optional) Provide background info or target hints for the binary:")
                if user_hint is None:
                    return
                user_hint = user_hint.strip()
                if user_hint:
                    add_hint_to_history(self.config, user_hint)
        else:
            user_hint = ida_kernwin.ask_str("", -1, "(Optional) Provide background info or target hints for the binary:")
            if user_hint is None:
                return
            user_hint = user_hint.strip()
            if user_hint:
                add_hint_to_history(self.config, user_hint)

        # 1. Collect candidate sub_* functions on the main thread
        targets: List[Tuple[int, str]] = []
        qty = ida_funcs.get_func_qty()
        for i in range(qty):
            f = ida_funcs.getn_func(i)
            if not f:
                continue
            name = ida_funcs.get_func_name(f.start_ea)
            if name and name.startswith("sub_"):
                targets.append((f.start_ea, name))

        if not targets:
            post_ida_msg("[BinaryLens] No sub_* functions found to rename.\n")
            return

        post_ida_msg(f"\n[BinaryLens] === Starting Subroutine Analysis ===\n")
        post_ida_msg(f"[BinaryLens] Found {len(targets)} candidate subroutines.\n")

        with self._run_lock:
            self._run_id += 1
            run_id = self._run_id
            self._cancel.clear()
            self.is_running = True

        if HAS_QT:
            try:
                parent = None
                try:
                    parent = QtWidgets.QApplication.activeWindow()
                except Exception:
                    pass
                self.progress_dialog = BinaryLensProgressDialog(len(targets), on_stop_cb=self.stop_analysis, parent=parent)
                self.progress_dialog.show()
            except Exception:
                self.progress_dialog = None

        self.worker_thread = threading.Thread(
            target=self._worker_rename_subs,
            args=(targets, user_hint, run_id),
            daemon=True
        )
        self.worker_thread.start()

    def _worker_rename_subs(self, targets: List[Tuple[int, str]], user_hint: str, run_id: int):
        start_time = time.time()
        try:
            batch_size = max(1, int(self.config.get("batch_size", 20)))
            total_renamed = 0
            decomp_flags = ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_WARNINGS
            max_func_size_kb = int(self.config.get("max_func_size_kb", 12))
            max_func_bytes = max_func_size_kb * 1024 if max_func_size_kb > 0 else 0
            MAX_BATCH_PROMPT_CHARS = 120000

            pending_queue = list(targets)
            batch_num = 0
            total_targets = len(targets)
            consecutive_failures = 0

            while pending_queue:
                if self._cancel.is_set() or run_id != self._run_id:
                    break

                batch_num += 1
                batch: List[Tuple[int, str]] = []
                decompiled_chunks: List[str] = []
                accumulated_chars = 0

                while pending_queue and len(batch) < batch_size:
                    if self._cancel.is_set() or run_id != self._run_id:
                        break

                    ea, name = pending_queue.pop(0)

                    processed_so_far = total_targets - len(pending_queue)
                    cur_elapsed = time.time() - start_time
                    def sync_status():
                        if getattr(self, "progress_dialog", None):
                            self.progress_dialog.update_progress(
                                processed_so_far, total_targets, total_renamed, cur_elapsed
                            )
                            self.progress_dialog.status_lbl.setText(
                                f"Batch {batch_num}: Decompiling {name} ({processed_so_far}/{total_targets})..."
                            )
                        return 1
                    ida_kernwin.execute_sync(sync_status, ida_kernwin.MFF_FAST)

                    chunk_res: List[str] = []
                    def decompile_single():
                        f = ida_funcs.get_func(ea)
                        if not f:
                            return 1
                        f_size = f.size()
                        if max_func_bytes > 0 and f_size > max_func_bytes:
                            post_ida_msg(f"[BinaryLens] Skipping {name} at 0x{ea:X}: {f_size / 1024:.1f} KB exceeds {max_func_size_kb} KB batch limit.\n")
                            return 1
                        try:
                            cfunc = ida_hexrays.decompile(f, flags=decomp_flags)
                            if cfunc:
                                lines = [ida_lines.tag_remove(sl.line) for sl in cfunc.get_pseudocode()]
                                chunk_res.append(truncate_pseudocode(lines, max_lines=150))
                        except Exception:
                            pass
                        return 1

                    sync_res = ida_kernwin.execute_sync(decompile_single, ida_kernwin.MFF_WRITE)
                    if sync_res < 0:
                        post_ida_msg(f"[BinaryLens] Warning: IDA rejected sync decompilation for {name}.\n")
                        continue

                    if chunk_res:
                        chunk_text = chunk_res[0]
                        chunk_len = len(chunk_text)
                        if batch and (accumulated_chars + chunk_len > MAX_BATCH_PROMPT_CHARS):
                            pending_queue.insert(0, (ea, name))
                            break
                        batch.append((ea, name))
                        decompiled_chunks.append(chunk_text)
                        accumulated_chars += chunk_len

                if not batch:
                    continue

                if self._cancel.is_set() or run_id != self._run_id:
                    break

                post_ida_msg(f"[BinaryLens] Processing batch {batch_num} ({len(batch)} functions)...\n")

                user_prompt = ""
                if user_hint:
                    user_prompt += f"User context / hints: {user_hint}\n\n"
                user_prompt += "Decompiled Functions:\n\n" + "\n\n/* ------------------ */\n\n".join(decompiled_chunks)

                submitted = {n: a for a, n in batch}
                submitted_hashes = {a: get_func_content_hash(a) for a, n in batch}

                def sync_query_status():
                    if getattr(self, "progress_dialog", None):
                        self.progress_dialog.status_lbl.setText(
                            f"Batch {batch_num}: Querying {self.config.get('model', 'model')}..."
                        )
                    return 1
                ida_kernwin.execute_sync(sync_query_status, ida_kernwin.MFF_FAST)

                raw_resp = call_llm(
                    SUB_REN_SYS_PROMPT,
                    user_prompt,
                    self.config,
                    on_log=post_ida_msg,
                    cancel_check=lambda: (self._cancel.is_set() or run_id != self._run_id)
                )

                if self._cancel.is_set() or run_id != self._run_id:
                    post_ida_msg("[BinaryLens] Analysis cancelled by user. Fencing pending batch mutations.\n")
                    break

                if not raw_resp:
                    consecutive_failures += 1
                    post_ida_msg(f"[BinaryLens] Batch {batch_num}: Failed to get response from model.\n")
                    if consecutive_failures >= 3:
                        post_ida_msg("[BinaryLens] Halting analysis: 3 consecutive batches failed. Check API key or settings.\n")
                        break
                    time.sleep(1.5)
                    continue

                consecutive_failures = 0
                summary, renames = parse_model_response(raw_resp)
                if summary:
                    post_ida_msg(f"[BinaryLens] Component Summary: {summary}\n")

                if not renames:
                    post_ida_msg(f"[BinaryLens] Batch {batch_num}: No valid renames returned by model.\n")
                    continue

                def apply_batch():
                    nonlocal total_renamed
                    if self._cancel.is_set() or run_id != self._run_id:
                        return 0
                    for orig_name, new_name in renames.items():
                        if self._cancel.is_set() or run_id != self._run_id:
                            return 0
                        # BL-002: Verify symbol is strictly in the submitted batch
                        expected_ea = submitted.get(orig_name)
                        if expected_ea is None:
                            continue
                        cur_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, orig_name)
                        if cur_ea != expected_ea:
                            continue
                        if get_func_content_hash(expected_ea) != submitted_hashes.get(expected_ea):
                            continue
                        if not new_name or new_name == orig_name:
                            continue
                        clean_name = sanitize_identifier(new_name)
                        if not clean_name:
                            continue
                        if ida_name.set_name(expected_ea, clean_name, ida_name.SN_NOWARN):
                            actual_name = ida_name.get_name(expected_ea)
                            total_renamed += 1
                            post_ida_msg(f"  [+] Renamed {orig_name} -> {actual_name}\n")
                            if summary:
                                pfn = ida_funcs.get_func(expected_ea)
                                if pfn and not ida_funcs.get_func_cmt(pfn, False):
                                    ida_funcs.set_func_cmt(pfn, f"Component: {summary}", False)
                    return 1

                ida_kernwin.execute_sync(apply_batch, ida_kernwin.MFF_WRITE)

                cur_elapsed = time.time() - start_time
                def sync_update_count():
                    if getattr(self, "progress_dialog", None):
                        processed_so_far = total_targets - len(pending_queue)
                        self.progress_dialog.update_progress(processed_so_far, total_targets, total_renamed, cur_elapsed)
                    return 1
                ida_kernwin.execute_sync(sync_update_count, ida_kernwin.MFF_FAST)

                time.sleep(0.05)

            total_time = time.time() - start_time
            mins = int(total_time // 60)
            secs = total_time % 60
            if mins > 0:
                elapsed_str = f"{mins}m {secs:.1f}s ({total_time:.1f}s)"
            else:
                elapsed_str = f"{total_time:.1f}s"

            if self._cancel.is_set() or run_id != self._run_id:
                msg_str = f"BinaryLens: Analysis stopped by user. Successfully renamed {total_renamed} functions in {elapsed_str}."
            else:
                msg_str = f"BinaryLens: Analysis complete! Successfully renamed {total_renamed} functions in {elapsed_str}."
            post_ida_msg(f"\n[BinaryLens] {msg_str}\n")

            def notify_done():
                if getattr(self, "progress_dialog", None):
                    try:
                        self.progress_dialog.mark_finished(total_renamed, aborted=(self._cancel.is_set() or run_id != self._run_id))
                    except Exception:
                        pass
                return 1

            ida_kernwin.execute_sync(notify_done, ida_kernwin.MFF_FAST)

        except Exception as e:
            post_ida_msg(f"[BinaryLens] Error during analysis: {e}\n")
        finally:
            with self._run_lock:
                if run_id == self._run_id:
                    self.is_running = False

    def rename_current_function_vars(self):
        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if not vdui or not vdui.cfunc:
            ida_kernwin.warning("Please open and activate a Hex-Rays pseudocode view.")
            return

        cfunc = vdui.cfunc
        entry_ea = cfunc.entry_ea
        lines = [ida_lines.tag_remove(sl.line) for sl in cfunc.get_pseudocode()]
        code_str = truncate_pseudocode(lines, max_lines=300)

        with self._run_lock:
            self._run_id += 1
            run_id = self._run_id

        threading.Thread(
            target=self._worker_rename_vars,
            args=(entry_ea, code_str, run_id),
            daemon=True
        ).start()

    def _worker_rename_vars(self, func_ea: int, code_str: str, run_id: int):
        start_time = time.time()
        post_ida_msg(f"[BinaryLens] Analyzing variables for function at 0x{func_ea:X}...\n")
        raw_resp = call_llm(
            VAR_REN_SYS_PROMPT,
            code_str,
            self.config,
            on_log=post_ida_msg,
            cancel_check=lambda: (self._cancel.is_set() or run_id != self._run_id)
        )

        if self._cancel.is_set() or run_id != self._run_id:
            return

        if not raw_resp:
            post_ida_msg("[BinaryLens] Failed to get response from model for variable renaming.\n")
            return

        summary, renames = parse_model_response(raw_resp)

        def apply_var_renames():
            if self._cancel.is_set() or run_id != self._run_id:
                return 0
            vdui = ida_hexrays.open_pseudocode(func_ea, ida_hexrays.OPF_REUSE)
            if not vdui or not vdui.cfunc:
                return 0

            cfunc = vdui.cfunc
            lvars = cfunc.get_lvars()
            renamed_count = 0

            for lvar in lvars:
                var_name = lvar.name
                if var_name in renames and renames[var_name] != var_name:
                    new_name = sanitize_identifier(renames[var_name])
                    if new_name and vdui.rename_lvar(lvar, new_name, True):
                        renamed_count += 1
                        post_ida_msg(f"  [+] Renamed variable {var_name} -> {new_name}\n")

            if summary:
                pfn = ida_funcs.get_func(func_ea)
                if pfn:
                    ida_funcs.set_func_cmt(pfn, summary, False)
                else:
                    ida_bytes.set_cmt(func_ea, summary, False)

            vdui.refresh_view(True)
            elapsed = time.time() - start_time
            post_ida_msg(f"[BinaryLens] Renamed {renamed_count} variables in {elapsed:.2f}s.\n")
            return 1

        ida_kernwin.execute_sync(apply_var_renames, ida_kernwin.MFF_WRITE)

    def explain_current_function(self):
        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if not vdui or not vdui.cfunc:
            ida_kernwin.warning("Please open and activate a Hex-Rays pseudocode view.")
            return

        lines = [ida_lines.tag_remove(sl.line) for sl in vdui.cfunc.get_pseudocode()]
        code_str = truncate_pseudocode(lines, max_lines=400)
        func_name = ida_funcs.get_func_name(vdui.cfunc.entry_ea)

        with self._run_lock:
            self._run_id += 1
            run_id = self._run_id

        def worker():
            start_time = time.time()
            post_ida_msg(f"[BinaryLens] Generating explanation for {func_name}...\n")
            resp = call_llm(
                EXPLAIN_SYS_PROMPT,
                code_str,
                self.config,
                on_log=post_ida_msg,
                cancel_check=lambda: (self._cancel.is_set() or run_id != self._run_id)
            )
            elapsed = time.time() - start_time
            if self._cancel.is_set() or run_id != self._run_id:
                return
            if resp:
                post_ida_msg(f"\n========== BinaryLens: Explanation for {func_name} (completed in {elapsed:.2f}s) ==========\n\n{resp}\n\n============================================================\n")
            else:
                post_ida_msg(f"[BinaryLens] Failed to generate explanation for {func_name} (after {elapsed:.2f}s).\n")

        threading.Thread(target=worker, daemon=True).start()


class _ActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class _UIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugin: BinaryLensPlugin):
        super().__init__()
        self.plugin = plugin

    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binarylens:rename_vars",
                "BinaryLens/"
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                "binarylens:explain_func",
                "BinaryLens/"
            )


def PLUGIN_ENTRY():
    return BinaryLensPlugin()


if __name__ == "__main__":
    _plugin = PLUGIN_ENTRY()
    _plugin.init()

