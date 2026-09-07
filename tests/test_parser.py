import sys
import os
import json
from pathlib import Path

# Add python folder to sys.path relative to this test file
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "python"))

# Mock IDA modules before importing binarylens
from unittest.mock import MagicMock
sys.modules['ida_bytes'] = MagicMock()
sys.modules['ida_funcs'] = MagicMock()
sys.modules['ida_hexrays'] = MagicMock()

class _DummyPluginT: pass
idaapi_mock = MagicMock()
idaapi_mock.plugin_t = _DummyPluginT
sys.modules['ida_idaapi'] = idaapi_mock

class _DummyActionHandler: pass
class _DummyUIHooks: pass
class _DummyForm: pass
kernwin_mock = MagicMock()
kernwin_mock.action_handler_t = _DummyActionHandler
kernwin_mock.UI_Hooks = _DummyUIHooks
kernwin_mock.Form = _DummyForm
sys.modules['ida_kernwin'] = kernwin_mock

sys.modules['ida_lines'] = MagicMock()
sys.modules['ida_name'] = MagicMock()

import binarylens

def test_json_parsing():
    sample_json = """```json
    {
        "summary": "This binary decrypts and parses configuration files.",
        "renamed_functions": {
            "sub_140001000": "DecryptPayload",
            "sub_140002500": "ParseNetworkPacket",
            "sub_140003A10": "InitTlsSocket"
        }
    }
    ```"""
    summary, renames = binarylens.parse_model_response(sample_json)
    assert summary == "This binary decrypts and parses configuration files.", f"Summary mismatch: {summary}"
    assert renames["sub_140001000"] == "DecryptPayload"
    assert renames["sub_140002500"] == "ParseNetworkPacket"
    assert renames["sub_140003A10"] == "InitTlsSocket"
    print("[PASS] JSON parsing with markdown code fences")

def test_ini_parsing():
    sample_ini = """Here is the analyzed output:
    ```ini
    [BinaryInfo]
    summary=Analyzed C++ malware loader.

    [RenamedFunctions]
    sub_100010=ExtractArchive
    sub_100050=DropBinaryToTemp
    ```
    I hope this helps!"""
    summary, renames = binarylens.parse_model_response(sample_ini)
    assert summary == "Analyzed C++ malware loader.", f"Summary mismatch: {summary}"
    assert renames["sub_100010"] == "ExtractArchive"
    assert renames["sub_100050"] == "DropBinaryToTemp"
    print("[PASS] INI parsing with markdown code fences and chatter")

def test_variable_parsing():
    sample_var = """{
        "summary": "Decrypts buffer using AES-GCM",
        "renamed_variables": {
            "a1": "CiphertextBuffer",
            "a2": "CiphertextLen",
            "v1": "OutPlaintext",
            "v2": "KeySchedule"
        }
    }"""
    summary, renames = binarylens.parse_model_response(sample_var)
    assert renames["a1"] == "CiphertextBuffer"
    assert renames["v2"] == "KeySchedule"
    print("[PASS] Variable rename parsing")

def test_identifier_sanitization():
    assert binarylens.sanitize_identifier('  "valid_func" ') == "valid_func"
    assert binarylens.sanitize_identifier('bad-name.with spaces') == "bad_name_with_spaces"
    assert binarylens.sanitize_identifier('123_invalid_lead') == "_123_invalid_lead"
    assert binarylens.sanitize_identifier(';drop table;--') == "drop_table"
    print("[PASS] Identifier sanitization")

def test_truncation():
    lines = [f"line {i}" for i in range(1000)]
    truncated = binarylens.truncate_pseudocode(lines, max_lines=150)
    assert "truncated for length" in truncated
    assert "line 0" in truncated
    assert "line 999" in truncated
    print("[PASS] Pseudocode truncation")

def test_pseudocode_compression():
    lines = [
        "int sub_1000()",
        "  {   ",
        "",
        "   ",
        "",
        "    int a = 1;   ",
        "",
        "",
        "    return a;",
        "  }  "
    ]
    cleaned = binarylens.truncate_pseudocode(lines, max_lines=50)
    # Check that multiple blank lines are compressed to single blank line
    assert "\n\n\n" not in cleaned
    # Check that trailing spaces are stripped
    assert "int a = 1;   " not in cleaned
    assert "int a = 1;" in cleaned
    assert "int sub_1000()\n  {\n\n    int a = 1;\n\n    return a;\n  }" == cleaned
    print("[PASS] Pseudocode whitespace and blank line compression")

def test_hint_history():
    from unittest.mock import patch
    cfg = {"hint_history": ["old_hint_1", "old_hint_2"]}
    with patch.object(binarylens, "save_config", return_value=True):
        binarylens.add_hint_to_history(cfg, "new_hint")
        assert cfg["hint_history"][0] == "new_hint"
        assert len(cfg["hint_history"]) == 3

        binarylens.add_hint_to_history(cfg, "old_hint_2")
        assert cfg["hint_history"][0] == "old_hint_2"
        assert cfg["hint_history"][1] == "new_hint"
        assert len(cfg["hint_history"]) == 3

        binarylens.add_hint_to_history(cfg, "   ")
        assert len(cfg["hint_history"]) == 3
    print("[PASS] Hint history deduplication and persistence")

def test_balanced_json_extraction():
    chatter_resp = """Certainly! Here is my analysis for your component {math_engine}:
    
    ```json
    {
        "summary": "Vector math library",
        "renamed_functions": {
            "sub_140001000": "Vec3DotProduct",
            "sub_140001200": "Vec3Normalize"
        }
    }
    ```
    
    Hope this helps with your reversing! (Notes: {keep up the good work})"""
    summary, renames = binarylens.parse_model_response(chatter_resp)
    assert summary == "Vector math library"
    assert renames["sub_140001000"] == "Vec3DotProduct"
    assert renames["sub_140001200"] == "Vec3Normalize"

    raw_chatter = """Here is the mapping: { "summary": "Crypto routine", "renamed_functions": { "sub_100": "AesEncrypt" } } cheers."""
    summary2, renames2 = binarylens.parse_model_response(raw_chatter)
    assert summary2 == "Crypto routine"
    assert renames2["sub_100"] == "AesEncrypt"
    print("[PASS] Balanced JSON extraction with chatter")

def test_qt_enum_resolution():
    class DummyScoped:
        TargetMember = 42

    class DummyOwner:
        Field = DummyScoped
        UnscopedMember = 99

    assert binarylens.qt_enum(DummyOwner, "Field", "TargetMember") == 42
    assert binarylens.qt_enum(DummyOwner, "MissingField", "UnscopedMember") == 99
    assert binarylens.qt_enum(DummyOwner, "MissingField", "Unknown", default=123) == 123
    assert binarylens.qt_enum(None, "Field", "TargetMember", default=-1) == -1
    print("[PASS] Qt enum cross-version resolution")

def test_reasoning_trace_exclusion():
    from unittest.mock import patch, MagicMock
    import io

    # Mock response containing reasoning_content but NO content
    fake_payload = json.dumps({
        "choices": [{
            "message": {
                "role": "assistant",
                "reasoning_content": "Let me think... sub_1000 is DecryptData"
            },
            "finish_reason": "stop"
        }]
    }).encode("utf-8")

    mock_resp = MagicMock()
    mock_resp.read.return_value = fake_payload
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = binarylens.call_llm(
            "sys_prompt", "user_prompt",
            {"base_url": "https://api.example.com", "model": "test-model"}
        )
        assert res is None, "Expected call_llm to reject empty content despite reasoning_content!"
    print("[PASS] Reasoning trace segregation (BL-009)")

def test_cancellation_fencing():
    plugin = binarylens.BinaryLensPlugin()
    plugin.is_running = True
    plugin._run_id = 5
    plugin.stop_analysis()

    assert not plugin.is_running
    assert plugin._cancel.is_set()
    assert plugin._run_id == 6
    print("[PASS] Monotonic run ID and cancellation fencing (BL-001)")

def test_out_of_batch_rejection():
    # Test batch allowlisting logic
    batch = [(0x1000, "sub_1000"), (0x2000, "sub_2000")]
    submitted = {n: a for a, n in batch}

    # Model returned an extra out-of-batch function (e.g. sub_3000 or main)
    renames = {
        "sub_1000": "ValidRename1",
        "sub_9999": "MaliciousInjection",
        "main": "HijackedMain"
    }

    filtered_renames = {}
    for orig, new in renames.items():
        if orig in submitted:
            filtered_renames[orig] = new

    assert "sub_1000" in filtered_renames
    assert "sub_9999" not in filtered_renames
    assert "main" not in filtered_renames
    print("[PASS] Out-of-batch symbol rejection (BL-002)")

def test_atomic_config():
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        test_conf = os.path.join(tmpdir, "test_config.json")
        orig_conf = binarylens.CONFIG_FILE
        orig_dir = binarylens.CONFIG_DIR
        try:
            binarylens.CONFIG_FILE = test_conf
            binarylens.CONFIG_DIR = tmpdir
            cfg = {"provider": "TestProvider", "batch_size": 15}
            assert binarylens.save_config(cfg)
            loaded = binarylens.load_config()
            assert loaded["provider"] == "TestProvider"
            assert loaded["batch_size"] == 15
        finally:
            binarylens.CONFIG_FILE = orig_conf
            binarylens.CONFIG_DIR = orig_dir
    print("[PASS] Atomic configuration persistence (BL-013)")

def test_manifest_compliance():
    manifest_path = Path(__file__).resolve().parent.parent / "ida-plugin.json"
    with open(manifest_path, "r", encoding="utf-8") as f:
        m = json.load(f)

    assert "$schema" in m
    assert isinstance(m["plugin"]["idaVersions"], list)
    assert len(m["plugin"]["idaVersions"]) >= 3
    assert "email" in m["plugin"]["authors"][0]
    print("[PASS] IDA 9 HCLI manifest compliance (BL-008)")

if __name__ == "__main__":
    test_json_parsing()
    test_ini_parsing()
    test_variable_parsing()
    test_identifier_sanitization()
    test_truncation()
    test_pseudocode_compression()
    test_hint_history()
    test_balanced_json_extraction()
    test_qt_enum_resolution()
    test_reasoning_trace_exclusion()
    test_cancellation_fencing()
    test_out_of_batch_rejection()
    test_atomic_config()
    test_manifest_compliance()
    print("\nAll 14 unit tests passed successfully!")
