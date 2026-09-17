from pathlib import Path
import re

JS = Path(__file__).parents[1] / "custom_components/home_assistant_chat/frontend/panel.js"
ROOT = Path(__file__).parents[1]

def test_frontend_has_no_native_dialogs():
    source = JS.read_text()
    assert not re.search(r"\b(?:alert|prompt)\s*\(", source)
    assert "window.confirm(" not in source and "globalThis.confirm(" not in source

def test_encryption_storage_and_protocol_markers():
    source = JS.read_text()
    assert "indexedDB" in source and "crypto.subtle" in source
    domain = (ROOT / "custom_components/home_assistant_chat/domain.py").read_text()
    assert "origin_server_id" in domain and "protocol_version" in domain and "ciphertext" in domain

def test_admin_bindings_and_csp_safe_markup():
    source=JS.read_text()
    assert 'd.querySelectorAll("[data-tab]")' in source
    assert 'data-user' in source and 'data-id' in source
    assert 'function unwrap' in source and 'key/request' in source
    assert not re.search(r'<[^>]+\s+on(?:click|error)\s*=', source)
