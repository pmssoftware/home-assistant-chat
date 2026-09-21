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
    assert 'await dbGetForScope(`legacy-key:${message.channel_id}:${epoch}`, scope)' in source
    assert 'objectStoreNames.contains("v")' in source
    assert 'migrateStorage(transaction,"values",target)' in source

def test_browser_crypto_storage_is_namespaced_by_server_and_user():
    source = JS.read_text()
    assert 'function storageScopeFor(state)' in source
    assert 'state?.server_id || state?.serverId || "local"' in source
    assert 'state?.user_id || ""' in source
    assert 'await configureStorageScope(this._state)' in source
    assert 'physicalStorageKey(key)' in source
    assert 'scope:${base64Url(encoder.encode(`${server}\\u0000${user}`))}:' in source
    assert 'async function migrateLegacyStorage(state, scope)' in source
    assert 'migration-v1' in source
    assert 'device?.id === oldIdentity.id && device?.user_id === state.user_id' in source
    assert 'key === "recovery-code" || key.startsWith("key:") || key.startsWith("legacy-key:")' in source

def test_account_switch_clears_cached_crypto_and_plaintext_state():
    source = JS.read_text()
    assert 'const previousScope = this._storageScope' in source
    assert 'this._plaintext = new Map(); this._draftValues = new Map(); this._keyRequests = new Set()' in source
    assert 'this._keyState = null; this._securityCode = null; this._recoveryFingerprint = null' in source

def test_unrecoverable_keys_have_an_explicit_new_key_fallback():
    source=JS.read_text()
    assert 'home_assistant_chat/key/reset' in source
    assert 'id="reset-key"' in source
    assert 'resetKey:"Start with a new key"' in source
    assert 'resetKey:"Mit neuem Schlüssel fortfahren"' in source
    assert 'device_id:identity.id,expected_epoch:channel.key_epoch || 1' in source
    assert 'await channelKey(channel.id,result.key_epoch,true,scope)' in source

def test_conflicting_same_epoch_keys_are_discarded_and_recovered():
    source = JS.read_text()
    assert 'async function channelKeyCommitment(key)' in source
    assert 'async function dbDelete(key)' in source
    assert 'state.commitments?.[offer.key_id]' in source
    assert 'offer.key_commitment !== expected' in source
    assert 'key_commitment:commitment' in source
    assert 'await channelKeyCommitment(existing) === expected' in source
    assert 'await dbDeleteForScope(`key:${channelId}:${epoch}`,scope)' in source
    assert 'key_commitment_conflict' in source

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
    assert 'this._keyRequests ||= new Set()' in source
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
    assert '<div class="header-actions">${(this._state?.is_admin ?? this._hass?.user?.is_admin)' in source
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

def test_announcements_are_presented_as_neutral_server_messages():
    source = JS.read_text()
    assert 'serverMessage:"Server"' in source
    assert 'current?.kind === "announcement" ? text.serverMessage' in source
    assert 'current?.kind !== "announcement" && message.sender_id === this._state?.user_id' in source
    assert 'current?.kind === "announcement" ? "announcement-message"' in source
    assert '.announcement-message{margin-left:auto;margin-right:auto' in source

def test_private_messages_deposit_recipient_keys_before_sending():
    source = JS.read_text()
    private_guard = 'if (channel.kind === "private")'
    send_call = 'const sent=await this.ws({type:"home_assistant_chat/send"'
    assert source.index(private_guard, source.index('async sendMessage')) < source.index(send_call, source.index('async sendMessage'))
    assert 'if (!delivery.peerTargets)' in source
    assert 'delivery.lookupFailed || delivery.peerFailed' in source
    assert 'key_offer_conflict' in source
    assert 'offlineSetupRequired:"This contact has not registered a Chat device yet.' in source
    assert 'offlineSetupRequired:"Dieser Kontakt hat noch kein Chat-Gerät registriert.' in source

def test_frontend_languages_are_extensible_and_fall_back_to_english():
    source = JS.read_text()
    assert 'return STRINGS[language] ? language : "en"' in source
    assert '.split(/[-_]/)[0].toLowerCase()' in source

def test_identity_ui_uses_numeric_local_and_federated_addresses():
    source = JS.read_text()
    assert 'IDENTITY_RE' in source
    assert 'NUMBER@HOST[:PORT]' in source
    assert '48392017@example.org:8123' in source
    assert 'validIdentity(handle)' in source
    assert 'identityNumber:"Identity number"' in source
    assert 'identityNumber:"Identitätsnummer"' in source
    assert 'federatedNotSupported' in source
    assert 'home_assistant_chat/private", handle' in source

def test_identity_is_visible_copyable_and_peer_uuid_is_not_contact_identifier():
    source = JS.read_text()
    assert 'identityMarkup()' in source
    assert 'copy-identity' in source and 'navigator.clipboard.writeText' in source
    assert 'this.identityMarkup()' in source
    assert 'String(channel.peer.identity || "")' in source
    assert 'esc(identity || "—")' in source
    assert 'channel.peer.id}</code>' not in source

def test_new_private_dialog_shows_own_identity_and_qr_controls():
    source = JS.read_text()
    start = source.index('privateDialog()')
    end = source.index('blockPrivate(channel)', start)
    dialog = source[start:end]
    assert '${this.identityMarkup()}' in dialog
    assert 'this.bindIdentityCopy(dialog)' in dialog
    assert '.show-identity-qr' in dialog

def test_group_sender_names_open_participant_actions():
    source = JS.read_text()
    assert 'current?.kind === "group" && message.sender_id !== this._state?.user_id' in source
    assert 'class="message-sender"' in source
    assert 'groupParticipantDialog(message)' in source
    assert 'group-peer-private' in source
    assert 'group-peer-silence' in source
    assert 'group-peer-block' in source
    assert 'group-peer-delete' in source

def test_recovery_bundle_is_client_side_pbkdf2_aes_gcm_and_idb_backed():
    source = JS.read_text()
    assert 'dbEntriesWithPrefixForScope(prefix, scope)' in source
    assert 'new Uint8Array(32)' in source and 'base64Url' in source
    assert 'PBKDF2' in source and 'SHA-256' in source
    assert 'iterations = 210000' in source
    assert 'crypto.subtle.encrypt({name:"AES-GCM", iv:nonce}' in source
    assert 'home_assistant_chat/recovery/set' in source
    assert 'home_assistant_chat/recovery/get' in source
    assert 'await dbPutForScope("recovery-code", code, scope)' in source
    assert 'this._recoveryUpdating' in source
    assert 'crypto.subtle.exportKey("raw", key)' in source
    assert 'crypto.subtle.importKey("raw", keyBytes' in source

def test_recovery_controls_warn_about_new_devices_and_are_localized():
    source = JS.read_text()
    assert 'recoveryWarning:' in source
    assert 'Ein neues Gerät benötigt ihn' in source
    assert 'recoveryMarkup()' in source
    assert 'create-recovery' in source and 'restore-recovery' in source
    assert 'navigator.clipboard.writeText(code)' in source

def test_recovery_updates_are_fingerprinted_and_imports_are_deduplicated():
    source = JS.read_text()
    assert 'entries.sort((a, b) => a.key_id.localeCompare(b.key_id))' in source
    assert 'crypto.subtle.digest("SHA-256", fingerprintInput)' in source
    assert 'this._recoveryFingerprint === fingerprint' in source
    assert 'const imported = await this.claimOffers()' in source
    assert 'if (existing && (!expected || await channelKeyCommitment(existing) === expected)) continue' in source
    assert 'return imported' in source
    assert 'iterations > 1000000' in source

def test_recovery_restore_validates_code_bundle_and_aes_key_sizes():
    source = JS.read_text()
    assert '^[A-Za-z0-9_-]{43}$' in source
    assert 'salt.length < 16' in source and 'nonce.length !== 12' in source
    assert 'item.key_id.length > 200' in source
    assert 'keyBytes.length !== 32' in source

def test_frontend_initialization_retries_without_duplicate_work():
    source = JS.read_text()
    assert 'if (!this._ready && !this._initializing) this.initialize()' in source
    assert 'this._initializing = true' in source
    assert 'this._channels ||= []' in source and 'this._messages ||= []' in source
    assert 'scheduleInitializationRetry()' in source
    assert 'const delays = [500, 1000, 2000, 5000, 10000, 30000]' in source
    assert 'if (this._retryTimer || this._disconnected || !this._hass) return' in source
    assert 'if (typeof this._unsubscribe !== "function") {' in source
    assert 'this._unsubscribe = await this._hass.connection.subscribeMessage' in source
    assert 'clearTimeout(this._retryTimer)' in source
    assert 'this._disconnected = true' in source
    assert 'Optional recovery sync must never block the chat UI.' in source

def test_core_state_initializes_before_encryption_and_admin_fallback_is_nonblocking():
    source = JS.read_text()
    assert 'await this.refreshState();\n      this._coreReady = true' in source
    assert 'async startEncryption()' in source
    assert source.index('await this.refreshState();\n      this._coreReady = true') < source.index('async startEncryption()')
    assert 'this._encryptionError' in source
    assert 'this._state?.is_admin ?? this._hass?.user?.is_admin' in source
    assert 'sanitizeError(error)' in source
    assert 'replace(/[^A-Za-z0-9_.:-]/g, "")' in source
    assert 'this._encryptionRetryTimer' in source

def test_identity_qr_ui_has_manual_confirmation_and_camera_lifecycle():
    source = JS.read_text()
    assert 'import "./qr-adapter.js"' in source
    assert 'showIdentityQr(identity)' in source
    assert 'show-identity-qr' in source and 'show-peer-qr' in source
    assert 'scan-identity' in source and 'this.scanQrDialog' in source
    assert 'navigator.mediaDevices.getUserMedia' in source
    assert 'facingMode:{ideal:"environment"}' in source
    assert 'input class="qr-file"' in source and 'type="file" accept="image/*"' in source
    assert 'getTracks().forEach((track) => track.stop())' in source
    assert 'globalThis.HAChatQR' in source
    assert 'globalThis.BarcodeDetector' in source
    assert 'onDecoded(identity)' in source
    assert 'this.text.qrPermission' in source and 'this.text.qrInvalid' in source
    assert 'QR_DEPENDENCY.md' not in source  # dependency note stays out of runtime UI

def test_identity_qr_federation_toggle_uses_configured_address_and_port():
    source = JS.read_text()
    assert 'this._state?.identity_address || identity' in source
    assert 'channel.peer.identity_address || identity' in source
    assert 'federation_qr_enabled' in source
    assert 'federation_address' in source and 'federation_port' in source
    assert 'federationQr:"Include federation address in identity QR codes"' in source
    assert 'federationQr:"Föderationsadresse in Identitäts-QR-Codes einschließen"' in source
    assert 'id="setting-federation-qr"' in source
    assert 'home_assistant_chat/settings' in source

def test_qr_dependencies_are_bundled_locally_with_licenses():
    frontend = ROOT / "custom_components/home_assistant_chat/frontend"
    adapter = (frontend / "qr-adapter.js").read_text()
    assert 'qrcode-generator.js' in adapter and 'qr-scanner.min.js' in adapter
    assert 'globalThis.HAChatQR' in adapter
    assert (frontend / "vendor/qrcode-generator.LICENSE").is_file()
    assert (frontend / "vendor/qr-scanner.LICENSE").is_file()
    notices = (ROOT / "THIRD_PARTY_NOTICES").read_text()
    assert "qrcode-generator" in notices and "qr-scanner" in notices


def test_deleted_message_markers_are_localized_and_admin_configurable():
    source = JS.read_text()
    assert 'messageDeleted:"Message deleted"' in source
    assert 'messageDeleted:"Nachricht gelöscht"' in source
    assert 'id="setting-deleted-markers"' in source
    assert 'show_deleted_messages:content.querySelector("#setting-deleted-markers").checked' in source
    assert '!message.deleted && message.sender_id === this._state?.user_id' in source
    assert '[data-message]:not(.deleted)' in source

def test_message_drafts_are_local_per_server_user_and_channel():
    source = JS.read_text()
    assert 'draft:${this._state?.server_id' in source
    assert 'this._draftValues.set(key,value)' in source
    assert 'value ? dbPut(key,value) : dbDelete(key)' in source
    assert 'addEventListener("input"' in source
    assert 'await dbDelete(this.draftKey(channel.id))' in source

def test_periodic_key_request_sync_covers_missed_events():
    source = JS.read_text()
    assert 'setInterval(() => this.syncKeyRequests().catch(() => {}), 10000)' in source
    assert 'pending_requests?.length' in source
    assert 'this._keyRequests.delete(`${channel.id}:${epoch}`)' in source

def test_frontend_uses_bounded_history_and_local_channel_cleanup():
    source = JS.read_text()
    assert 'home_assistant_chat/history' in source
    assert 'has_older_messages' in source and 'oldest_cursor' in source
    assert 'loadOlderMessages()' in source
    assert 'deleteLocalChannelState(event.channel_id' in source
    assert 'event.channel_id || event.request?.channel_id' in source

def test_frontend_consumes_batched_key_states():
    source = JS.read_text()
    assert 'new Map(Object.entries(this._state.key_states || {}))' in source
    assert 'this._keyStates?.get(channel.id)' in source
    assert 'home_assistant_chat/key/states' in source
    assert 'const states=new Map((response.states || [])' in source
    assert 'this._keyStates=states' in source

def test_render_preserves_composer_focus_and_message_scroll():
    source = JS.read_text()
    assert 'this.shadowRoot.activeElement?.id === "message-input"' in source
    assert 'focus({preventScroll:true})' in source
    assert 'nextMessages.scrollTop=priorScroll.atBottom' in source

def test_mobile_layout_uses_safe_area_dvh_and_horizontal_channels():
    source = JS.read_text()
    assert 'id="responsive-chat-style"' in source
    assert 'height:100dvh' in source
    assert 'env(safe-area-inset-bottom)' in source
    assert 'overflow-x:auto' in source

def test_ios_visual_viewport_lifecycle_and_composer_visibility():
    source = JS.read_text()
    assert 'window.visualViewport' in source
    assert 'addEventListener("scroll",this._viewportHandler' in source
    assert 'removeEventListener("scroll",this._viewportHandler' in source
    assert 'safe-area-inset-top' in source
    assert 'scrollIntoView({block:"nearest"' in source

def test_decrypted_plaintext_is_cached_to_prevent_placeholder_layout_jumps():
    source = JS.read_text()
    assert 'this._plaintext ||= new Map()' in source
    assert 'this._plaintext.set(sent.message.id,value)' in source
    assert 'this._plaintext?.has(message.id) ? esc(this._plaintext.get(message.id))' in source
    assert 'const currentInput=this.shadowRoot.querySelector("#message-input")' in source
