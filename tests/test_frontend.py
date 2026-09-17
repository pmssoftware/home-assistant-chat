from pathlib import Path

JS = Path(__file__).parents[1] / "custom_components/home_assistant_chat/frontend/panel.js"
ROOT = Path(__file__).parents[1]

def test_frontend_has_no_native_dialogs():
    source = JS.read_text()
    import re
    assert not re.search(r"\b(?:alert|prompt)\s*\(", source)
    assert "window.confirm(" not in source and "globalThis.confirm(" not in source

def test_encryption_storage_and_protocol_markers():
    source = JS.read_text()
    assert "indexedDB" in source and "crypto.subtle" in source
    domain = (ROOT / "custom_components/home_assistant_chat/domain.py").read_text()
    assert "origin_server_id" in domain and "protocol_version" in domain and "ciphertext" in domain
