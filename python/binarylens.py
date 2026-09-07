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

PROVIDERS = {
    "Gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "default_model": "gemini-2.5-pro",
        "models": ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-1.5-pro"],
    },
    "DeepSeek": {
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "models": ["deepseek-chat", "deepseek-reasoner"],
    },
    "OpenAI": {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o",
        "models": ["gpt-4o", "gpt-4o-mini", "o3-mini", "gpt-5"],
    },
    "OpenRouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "anthropic/claude-3.7-sonnet",
        "models": [
            "anthropic/claude-3.7-sonnet",
            "deepseek/deepseek-r1",
            "google/gemini-2.5-pro",
            "meta-llama/llama-3.3-70b-instruct"
        ],
    },
    "Ollama (Local)": {
        "base_url": "http://localhost:11434/v1",
        "default_model": "qwen2.5-coder:32b",
        "models": ["qwen2.5-coder:32b", "deepseek-coder-v2", "llama3.3:latest"],
    },
    "Custom / Other": {
        "base_url": "http://localhost:1234/v1",
        "default_model": "custom-model",
        "models": ["custom-model"],
    }
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


class SettingsDialog(ida_kernwin.Form):
    """Configuration form for BinaryLens."""
    def __init__(self, config: dict):
        self.config = config
        providers_list = list(PROVIDERS.keys())
        current_p_idx = 0
        if config.get("provider") in providers_list:
            current_p_idx = providers_list.index(config["provider"])

        ida_kernwin.Form.__init__(
            self,
            r"""STARTITEM {id_provider}
BUTTON YES Save
BUTTON CANCEL Cancel
BinaryLens Configuration

<#Select LLM Provider#Provider  :{id_provider}>
<#API Base URL (OpenAI-compatible endpoint)#Base URL  :{id_base_url}>
<#Model Name (e.g. gemini-2.5-pro, deepseek-chat, gpt-4o, qwen2.5-coder:32b)#Model     :{id_model}>
<#API Key (Leave empty for local Ollama)#API Key   :{id_api_key}>
<#Number of subroutines to send per batch request#Batch Size:{id_batch_size}>
""",
            {
                "id_provider": ida_kernwin.Form.DropdownListControl(
                    items=providers_list,
                    readonly=True,
                    selval=current_p_idx
                ),
                "id_base_url": ida_kernwin.Form.StringInput(value=config.get("base_url", ""), width=60),
                "id_model": ida_kernwin.Form.StringInput(value=config.get("model", ""), width=60),
                "id_api_key": ida_kernwin.Form.StringInput(value=config.get("api_key", ""), width=60),
                "id_batch_size": ida_kernwin.Form.NumericInput(value=config.get("batch_size", 40), tp=ida_kernwin.Form.FT_INT),
            }
        )

    def OnDropdownChange(self, fid):
        providers_list = list(PROVIDERS.keys())
        sel_idx = self.id_provider.value
        if 0 <= sel_idx < len(providers_list):
            p_name = providers_list[sel_idx]
            info = PROVIDERS[p_name]
            self.SetControlValue(self.id_base_url, info["base_url"])
            self.SetControlValue(self.id_model, info["default_model"])
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
        dialog = SettingsDialog(self.config)
        dialog.Compile()
        ok = dialog.Execute()
        if ok == 1:
            providers_list = list(PROVIDERS.keys())
            sel_idx = dialog.id_provider.value
            self.config["provider"] = providers_list[sel_idx] if 0 <= sel_idx < len(providers_list) else "Custom"
            self.config["base_url"] = dialog.id_base_url.value.strip()
            self.config["model"] = dialog.id_model.value.strip()
            self.config["api_key"] = dialog.id_api_key.value.strip()
            self.config["batch_size"] = max(1, int(dialog.id_batch_size.value))
            save_config(self.config)
            ida_kernwin.info(f"BinaryLens settings saved.\nActive Model: {self.config['model']}\nBase URL: {self.config['base_url']}")
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
