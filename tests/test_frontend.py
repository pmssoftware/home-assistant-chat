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
    assert 'dialog.querySelectorAll("[data-tab]")' in source
    assert 'user/access' in source and 'admin/mute' in source
    assert 'function unwrapChannelKey' in source and 'key/request' in source
    assert 'private/delete' in source and 'user/block' in source
    assert 'show_security_details' in source and 'keySecurityCode' in source
    assert 'channel/edit' in source and 'channel-members' in source
    assert 'revoke-device' in source and 'block-private' in source and 'delete-private' in source
    assert 'promptForEdit' not in source
    assert not re.search(r'<[^>]+\s+on(?:click|error)\s*=', source)

def test_registered_panel_name_matches_custom_element():
    panel_source = (ROOT / "custom_components/home_assistant_chat/panel.py").read_text()
    match = re.search(r'PANEL_NAME\s*=\s*"([^"]+)"', panel_source)
    assert match
    assert f'customElements.define("{match.group(1)}"' in JS.read_text()

def test_chat_actions_and_composer_use_the_requested_layout():
    source = JS.read_text()
    assert '<aside class="side"><h2>${text.chat}</h2>${channels.map' in source
    assert '<div class="header-actions"><button class="button" id="new-private">' in source
    assert '<div class="message-head"><small>' in source
    assert '<ha-icon icon="mdi:delete-outline"' in source
    assert 'aria-label="${esc(text.delete)}"' in source
    assert ':host{display:block;height:100dvh' in source
    assert '.messages{flex:1;min-height:0;overflow:auto' in source
    assert '.compose{display:flex;flex:0 0 auto' in source

def test_deleted_message_markers_are_localized_and_admin_configurable():
    source = JS.read_text()
    assert 'messageDeleted:"Message deleted"' in source
    assert 'messageDeleted:"Nachricht gelöscht"' in source
    assert 'id="setting-deleted-markers"' in source
    assert 'show_deleted_messages:content.querySelector("#setting-deleted-markers").checked' in source
    assert '!message.deleted && message.sender_id === this._state?.user_id' in source
    assert '[data-message]:not(.deleted)' in source
