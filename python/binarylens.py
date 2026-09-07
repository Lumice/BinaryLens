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
import urllib.error
import urllib.request
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
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                config = DEFAULT_CONFIG.copy()
                config.update(data)
                return config
        except Exception as e:
            ida_kernwin.msg(f"[BinaryLens] Warning: Failed to load config: {e}\n")
    return DEFAULT_CONFIG.copy()

def save_config(config: dict) -> bool:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        ida_kernwin.msg(f"[BinaryLens] Error saving config: {e}\n")
        return False

def sanitize_identifier(name: str) -> str:
    """Ensure a string is a valid C/IDA identifier."""
    name = name.strip().strip('"').strip("'")
    cleaned = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    if cleaned and cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned

def parse_model_response(raw_text: str) -> Tuple[str, Dict[str, str]]:
    """
    Extracts summary and mapping (functions or variables) from JSON or INI format.
    Handles code fences, markdown wrapping, and malformed responses.
    """
    summary = ""
    mapping: Dict[str, str] = {}

    text = raw_text.strip()

    # 1. Try extracting JSON
    json_match = re.search(r'\{.*\}', text, re.DOTALL)
    if json_match:
        try:
            data = json.loads(json_match.group(0))
            summary = data.get("summary", "")
            
            # Function mappings
            funcs = data.get("renamed_functions") or data.get("RenamedFunctions") or data.get("functions")
            if isinstance(funcs, dict):
                for k, v in funcs.items():
                    if isinstance(k, str) and isinstance(v, str):
                        mapping[k.strip()] = sanitize_identifier(v)

            # Variable mappings
            vars_dict = data.get("renamed_variables") or data.get("RenamedLocals") or data.get("variables")
            if isinstance(vars_dict, dict):
                for k, v in vars_dict.items():
                    if isinstance(k, str) and isinstance(v, str):
                        mapping[k.strip()] = sanitize_identifier(v)

            if mapping:
                return summary, mapping
        except Exception:
            pass

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
    on_log=None
) -> Optional[str]:
    """Sends a chat completion request to an OpenAI-compatible endpoint."""
    base_url = config.get("base_url", "").strip().rstrip("/")
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = "https://" + base_url

    endpoint = base_url if base_url.endswith("/chat/completions") else f"{base_url}/chat/completions"
    model = config.get("model", "gemini-2.5-pro")
    api_key = config.get("api_key", "").strip()
    timeout = config.get("timeout_sec", 180)

    if on_log:
        on_log(f"[BinaryLens] Dispatching request to {endpoint} (Model: {model})...\n")

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

    body_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(endpoint, data=body_bytes, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")

    ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8")
            data = json.loads(resp_body)
            content = data["choices"][0]["message"]["content"]
            return content
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        if on_log:
            on_log(f"[BinaryLens] HTTP Error {e.code}: {err_msg}\n")
        return None
    except Exception as e:
        if on_log:
            on_log(f"[BinaryLens] Request failed: {e}\n")
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
            form_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.ExpandingFieldsGrow)

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
            self._echo_pwd = getattr(QtWidgets.QLineEdit.EchoMode, "Password", getattr(QtWidgets.QLineEdit, "Password", 2))
            self._echo_norm = getattr(QtWidgets.QLineEdit.EchoMode, "Normal", getattr(QtWidgets.QLineEdit, "Normal", 0))

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
                known_defaults = {"", "llama3", "gemini-2.5-pro", "gemini-2.5-flash", "deepseek-chat", "deepseek-v4-pro", "gpt-4o-mini", "local-model"}
                if cur_m in known_defaults:
                    if "OpenCode" in p_name:
                        self.model_edit.setText("deepseek-v4-pro")
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
                self.test_status.setStyleSheet("color: red;")
                self.test_status.setText("Base URL cannot be empty.")
                return

            self.test_status.setStyleSheet("color: #0066cc;")
            self.test_status.setText("Testing connection...")
            self.test_btn.setEnabled(False)

            def do_test():
                err = None
                try:
                    messages = [{"role": "user", "content": "Respond with OK"}]
                    resp = query_llm(base_url, api_key, model, messages, temperature=0.0)
                    if not resp:
                        err = "No response from endpoint."
                except Exception as ex:
                    err = str(ex)

                def on_done():
                    self.test_btn.setEnabled(True)
                    if err:
                        self.test_status.setStyleSheet("color: red;")
                        self.test_status.setText(f"Failed: {err[:50]}")
                    else:
                        self.test_status.setStyleSheet("color: green; font-weight: bold;")
                        self.test_status.setText("Connection successful!")

                QtCore.QTimer.singleShot(0, on_done)

            threading.Thread(target=do_test, daemon=True).start()

        def get_values(self):
            return {
                "preset": self.preset_combo.currentText(),
                "base_url": self.base_url_edit.text().strip(),
                "model": self.model_edit.text().strip(),
                "api_key": self.api_key_edit.text().strip(),
                "batch_size": self.batch_size_spin.value(),
            }


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
        self.worker_thread: Optional[threading.Thread] = None
        self.is_running = False

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            ida_kernwin.msg("[BinaryLens] Hex-Rays decompiler not detected. Plugin disabled.\n")
            return ida_idaapi.PLUGIN_SKIP

        self._register_actions()
        ida_kernwin.msg("[BinaryLens] Loaded successfully. (Edit -> BinaryLens)\n")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.show_settings()

    def term(self):
        self._unregister_actions()

    def _register_actions(self):
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

        # Action 2: Settings
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

        # Action 3: Rename Variables (Context Menu)
        rename_vars_desc = ida_kernwin.action_desc_t(
            "binarylens:rename_vars",
            "BinaryLens: Rename Variables",
            _ActionHandler(self.rename_current_function_vars),
            "",
            "Rename local variables in current function using LLM",
            -1
        )
        ida_kernwin.register_action(rename_vars_desc)

        # Action 4: Explain Function
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
            self.ui_hooks.unhook()
        ida_kernwin.unregister_action("binarylens:rename_subs")
        ida_kernwin.unregister_action("binarylens:settings")
        ida_kernwin.unregister_action("binarylens:rename_vars")
        ida_kernwin.unregister_action("binarylens:explain_func")

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
                accepted_code = getattr(QtWidgets.QDialog.DialogCode, "Accepted", getattr(QtWidgets.QDialog, "Accepted", 1))
                if res == 1 or res == accepted_code:
                    vals = dialog.get_values()
                    self.config.update(vals)
                    save_config(self.config)
                    ida_kernwin.info(f"BinaryLens settings saved.\nModel: {self.config['model']}\nBase URL: {self.config['base_url']}")
                return
            except Exception as e:
                ida_kernwin.msg(f"[BinaryLens] Qt dialog error, falling back to IDA form: {e}\n")

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
        if self.is_running:
            ida_kernwin.warning("[BinaryLens] Analysis is already in progress!")
            return

        user_hint = ida_kernwin.ask_str("", 0, "(Optional) Provide background info or target hints for the binary:")
        if user_hint is None:
            return

        self.worker_thread = threading.Thread(
            target=self._worker_rename_subs,
            args=(user_hint,),
            daemon=True
        )
        self.worker_thread.start()

    def _worker_rename_subs(self, user_hint: str):
        self.is_running = True
        try:
            ida_kernwin.msg("\n[BinaryLens] === Starting Subroutine Analysis ===\n")

            # 1. Collect all sub_* functions
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
                ida_kernwin.msg("[BinaryLens] No sub_* functions found to rename.\n")
                return

            ida_kernwin.msg(f"[BinaryLens] Found {len(targets)} candidate subroutines.\n")

            # 2. Batch and process
            batch_size = self.config.get("batch_size", 40)
            total_renamed = 0

            for batch_start in range(0, len(targets), batch_size):
                batch = targets[batch_start:batch_start + batch_size]
                ida_kernwin.msg(f"[BinaryLens] Processing batch {batch_start // batch_size + 1} ({len(batch)} functions)...\n")

                decompiled_chunks: List[str] = []
                for ea, name in batch:
                    f = ida_funcs.get_func(ea)
                    if not f:
                        continue
                    try:
                        cfunc = ida_hexrays.decompile(f)
                        if cfunc:
                            lines = [ida_lines.tag_remove(sl.line) for sl in cfunc.get_pseudocode()]
                            decompiled_chunks.append("\n".join(lines))
                    except Exception:
                        continue

                if not decompiled_chunks:
                    continue

                user_prompt = ""
                if user_hint:
                    user_prompt += f"User context / hints: {user_hint}\n\n"
                user_prompt += "Decompiled Functions:\n\n" + "\n\n/* ------------------ */\n\n".join(decompiled_chunks)

                raw_resp = call_llm(
                    SUB_REN_SYS_PROMPT,
                    user_prompt,
                    self.config,
                    on_log=ida_kernwin.msg
                )

                if not raw_resp:
                    ida_kernwin.msg(f"[BinaryLens] Failed to get response for batch {batch_start // batch_size + 1}.\n")
                    continue

                summary, renames = parse_model_response(raw_resp)
                if summary:
                    ida_kernwin.msg(f"[BinaryLens] Component Summary: {summary}\n")

                def apply_batch():
                    nonlocal total_renamed
                    for orig_name, new_name in renames.items():
                        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, orig_name)
                        if ea != ida_idaapi.BADADDR and new_name and new_name != orig_name:
                            if ida_name.set_name(ea, new_name, ida_name.SN_NOWARN | ida_name.SN_FORCE):
                                total_renamed += 1
                                ida_kernwin.msg(f"  [+] Renamed {orig_name} -> {new_name}\n")
                    return 1

                ida_kernwin.execute_sync(apply_batch, ida_kernwin.MFF_WRITE)

            ida_kernwin.msg(f"\n[BinaryLens] Analysis complete! Successfully renamed {total_renamed} functions.\n")
            ida_kernwin.info(f"BinaryLens: Renamed {total_renamed} functions.")

        except Exception as e:
            ida_kernwin.msg(f"[BinaryLens] Error during analysis: {e}\n")
        finally:
            self.is_running = False

    def rename_current_function_vars(self):
        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if not vdui or not vdui.cfunc:
            ida_kernwin.warning("Please open and activate a Hex-Rays pseudocode view.")
            return

        cfunc = vdui.cfunc
        entry_ea = cfunc.entry_ea
        lines = [ida_lines.tag_remove(sl.line) for sl in cfunc.get_pseudocode()]
        code_str = "\n".join(lines)

        threading.Thread(
            target=self._worker_rename_vars,
            args=(entry_ea, code_str),
            daemon=True
        ).start()

    def _worker_rename_vars(self, func_ea: int, code_str: str):
        ida_kernwin.msg(f"[BinaryLens] Analyzing variables for function at 0x{func_ea:X}...\n")
        raw_resp = call_llm(
            VAR_REN_SYS_PROMPT,
            code_str,
            self.config,
            on_log=ida_kernwin.msg
        )

        if not raw_resp:
            ida_kernwin.warning("[BinaryLens] Failed to get response from model.")
            return

        summary, renames = parse_model_response(raw_resp)

        def apply_var_renames():
            vdui = ida_hexrays.open_pseudocode(func_ea, ida_hexrays.OPF_REUSE)
            if not vdui or not vdui.cfunc:
                return 0

            cfunc = vdui.cfunc
            lvars = cfunc.get_lvars()
            renamed_count = 0

            for lvar in lvars:
                var_name = lvar.name
                if var_name in renames and renames[var_name] != var_name:
                    new_name = renames[var_name]
                    if vdui.rename_lvar(lvar, new_name, True):
                        renamed_count += 1
                        ida_kernwin.msg(f"  [+] Renamed variable {var_name} -> {new_name}\n")

            if summary:
                ida_bytes.set_cmt(func_ea, summary, False)

            vdui.refresh_view(True)
            ida_kernwin.msg(f"[BinaryLens] Renamed {renamed_count} variables.\n")
            return 1

        ida_kernwin.execute_sync(apply_var_renames, ida_kernwin.MFF_WRITE)

    def explain_current_function(self):
        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if not vdui or not vdui.cfunc:
            ida_kernwin.warning("Please open and activate a Hex-Rays pseudocode view.")
            return

        lines = [ida_lines.tag_remove(sl.line) for sl in vdui.cfunc.get_pseudocode()]
        code_str = "\n".join(lines)
        func_name = ida_funcs.get_func_name(vdui.cfunc.entry_ea)

        def worker():
            ida_kernwin.msg(f"[BinaryLens] Generating explanation for {func_name}...\n")
            resp = call_llm(EXPLAIN_SYS_PROMPT, code_str, self.config, on_log=ida_kernwin.msg)
            if resp:
                ida_kernwin.msg(f"\n========== BinaryLens: Explanation for {func_name} ==========\n\n{resp}\n\n============================================================\n")
            else:
                ida_kernwin.warning("Failed to generate explanation.")

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
