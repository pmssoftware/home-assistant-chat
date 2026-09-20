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

def test_browser_key_store_migrates_legacy_identity_and_channel_keys():
    source = JS.read_text()
    assert 'indexedDB.open("ha-chat-device-v1", 3)' in source
    assert 'key === "identity"' in source
    assert 'primary:"device", legacy:"legacy-device"' in source
    assert 'key.startsWith("channel:")' in source
    assert 'legacy:`legacy-key:${suffix}`' in source
    assert 'existingRequest.result === undefined ? migrated.primary : migrated.legacy' in source
    assert 'await dbGet(`legacy-key:${message.channel_id}:${epoch}`)' in source
    assert 'objectStoreNames.contains("v")' in source
    assert 'migrateStorage(transaction,"values",target)' in source

def test_unrecoverable_keys_have_an_explicit_new_key_fallback():
    source=JS.read_text()
    assert 'home_assistant_chat/key/reset' in source
    assert 'id="reset-key"' in source
    assert 'resetKey:"Start with a new key"' in source
    assert 'resetKey:"Mit neuem Schlüssel fortfahren"' in source
    assert 'device_id:identity.id,expected_epoch:channel.key_epoch || 1' in source
    assert 'await channelKey(channel.id,result.key_epoch,true)' in source

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

def test_key_recovery_requests_are_deduplicated_and_reset_errors_are_localized():
    source = JS.read_text()
    assert 'this._keyRequests = new Set()' in source
    assert '!this._keyRequests.has(requestKey)' in source
    assert 'this._keyRequests.add(requestKey)' in source
    assert 'this._keyRequests.delete(requestKey)' in source
    assert 'resetError:' in source
    assert 'this._error = this.text.resetError' in source

def test_registered_panel_name_matches_custom_element():
    panel_source = (ROOT / "custom_components/home_assistant_chat/panel.py").read_text()
    match = re.search(r'PANEL_NAME\s*=\s*"([^"]+)"', panel_source)
    assert match
    assert f'customElements.define("{match.group(1)}"' in JS.read_text()

def test_panel_url_is_cache_busted_by_manifest_version():
    panel_source = (ROOT / "custom_components/home_assistant_chat/panel.py").read_text()
    assert 'manifest.json' in panel_source
    assert 'module_url=f"{STATIC_PATH}/panel.js?v={quote(_frontend_version()' in panel_source
    assert 'StaticPathConfig(STATIC_PATH, str(www), False)' in panel_source

def test_chat_actions_and_composer_use_the_requested_layout():
    source = JS.read_text()
    assert '<div class="side-top"><h2>${text.chat}</h2><button class="button" id="new-private"' in source
    assert '<div class="header-actions">${this._state?.is_admin' in source
    assert 'height:var(--chat-header-height)' in source
    assert '<div class="message-head"><small>' in source
    assert '<ha-icon icon="mdi:delete-outline"' in source
    assert 'aria-label="${esc(text.delete)}"' in source
    assert ':host{display:block;height:100dvh' in source
    assert '.messages{flex:1;min-height:0;overflow:auto' in source
    assert '.compose{display:flex;flex:0 0 auto' in source

def test_role_specific_settings_windows():
    source = JS.read_text()
    assert 'id="admin">${text.admin}' in source
    assert 'id="user-settings">${text.settings}' in source
    assert 'async userSettingsDialog()' in source
    assert 'home_assistant_chat/user/blocked' in source
    assert 'class="button unblock-user"' in source
    assert 'home_assistant_chat/user/unblock' in source
    assert 'this.shadowRoot.querySelector("#user-settings")' in source

def test_private_chat_overflow_menu_contains_contact_actions():
    source = JS.read_text()
    assert 'icon="mdi:dots-vertical"' in source
    assert 'class="button private-info"' in source
    assert 'class="button silence-private"' in source
    assert 'class="button danger block-private"' in source
    assert 'class="button danger delete-private"' in source
    assert 'home_assistant_chat/private/silence' in source
    assert 'this.privateMenu(channel,"sidebar")' in source
    assert 'this.privateMenu(current)' in source

def test_private_chats_use_the_contact_name_instead_of_generic_label():
    source = JS.read_text()
    assert 'if (channel?.kind === "private") return channel.peer?.name || this.text.private' in source
    assert 'current?.kind === "private" && peer' in source
    assert '<span class="peer-avatar">${esc(initials(peer.name))}</span><h3>${esc(peer.name)}</h3>' in source

def test_compact_icon_controls():
    source = JS.read_text()
    assert 'id="new-private" aria-label="${esc(text.private)}" title="${esc(text.private)}">+</button>' in source
    assert '.button.delete-message{display:grid;place-items:center;flex:0 0 28px;width:28px;height:28px;padding:0;border:0;background:transparent}' in source
    assert '.button.delete-message:hover{' in source
    assert '.delete-message ha-icon{--mdc-icon-size:18px}' in source

def test_default_channel_names_follow_personal_browser_language():
    source = JS.read_text()
    assert 'announcements:"Announcements"' in source
    assert 'announcements:"Ankündigungen"' in source
    assert 'globalThis.navigator?.language' in source
    assert 'globalThis.navigator?.languages?.[0]' in source
    assert source.index('globalThis.navigator?.languages?.[0]') < source.index('this._hass?.language')
    assert 'if (channel?.id === "public") return this.text.publicChat' in source
    assert 'if (channel?.id === "announcements") return this.text.announcements' in source
    assert '${esc(this.channelName(channel))}' in source

def test_frontend_languages_are_extensible_and_fall_back_to_english():
    source = JS.read_text()
    assert 'return STRINGS[language] ? language : "en"' in source
    assert '.split(/[-_]/)[0].toLowerCase()' in source


def test_deleted_message_markers_are_localized_and_admin_configurable():
    source = JS.read_text()
    assert 'messageDeleted:"Message deleted"' in source
    assert 'messageDeleted:"Nachricht gelöscht"' in source
    assert 'id="setting-deleted-markers"' in source
    assert 'show_deleted_messages:content.querySelector("#setting-deleted-markers").checked' in source
    assert '!message.deleted && message.sender_id === this._state?.user_id' in source
    assert '[data-message]:not(.deleted)' in source
