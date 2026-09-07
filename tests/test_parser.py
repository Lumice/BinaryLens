import sys
import os

# Add python folder to sys.path
sys.path.insert(0, os.path.abspath("python"))

# Mock IDA modules before importing binarylens
from unittest.mock import MagicMock
sys.modules['ida_bytes'] = MagicMock()
sys.modules['ida_funcs'] = MagicMock()
sys.modules['ida_hexrays'] = MagicMock()
sys.modules['ida_idaapi'] = MagicMock()
sys.modules['ida_kernwin'] = MagicMock()
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
    print("[PASS] Identifier sanitization")

def test_truncation():
    lines = [f"line {i}" for i in range(1000)]
    truncated = binarylens.truncate_pseudocode(lines, max_lines=150)
    assert "truncated for length" in truncated
    assert "line 0" in truncated
    assert "line 999" in truncated
    print("[PASS] Pseudocode truncation")

if __name__ == "__main__":
    test_json_parsing()
    test_ini_parsing()
    test_variable_parsing()
    test_identifier_sanitization()
    test_truncation()
    print("\nAll unit tests passed successfully!")
