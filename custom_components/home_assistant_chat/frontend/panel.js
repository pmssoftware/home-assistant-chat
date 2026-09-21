/* Home Assistant Chat: browser-only experimental encryption, no native dialogs. */
import "./qr-adapter.js";
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const b64 = (value) => btoa(String.fromCharCode(...new Uint8Array(value)));
const raw = (value) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
const initials = (value) => String(value || "?").trim().split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
// Local identities are numeric; federation appends a host and optional port.
const IDENTITY_RE = /^[1-9]\d{7}(?:@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::\d{1,5})?)?$/;
const validIdentity = (value) => IDENTITY_RE.test(String(value || "").trim());

const STRINGS = {
  en: {
    chat:"Chat", private:"Private chat", device:"Browser device", handle:"Enter an identity number (for example 48392017 or 48392017@example.org:8123).", identityNumber:"Identity number", ownIdentity:"Your identity", copyIdentity:"Copy identity", copiedIdentity:"Copied", invalidIdentity:"Enter a valid identity number: NUMBER or NUMBER@HOST[:PORT].", federatedNotSupported:"Federated identities are not supported by this server yet.", send:"Send", write:"Write a message",
    cancel:"Cancel", continue:"Continue", delete:"Delete", deleteBoth:"Delete entire chat", block:"Block", close:"Close", admin:"Administration",
    channels:"Channels", moderation:"Moderation", users:"Users / Access", devices:"Devices / Encryption", settings:"Settings", name:"Name",
    members:"Members", create:"Create", edit:"Edit", save:"Save", mute:"Mute", unmute:"Unmute", revoke:"Revoke", unblock:"Unblock", blockedUsers:"Blocked users",
    waiting:"Waiting for an active device to share the channel key…", noMessages:"No messages yet", encrypted:"Encrypted message — channel key unavailable",
    security:"Security code", deviceCount:"Devices", enabled:"Chat enabled", allowUsers:"Allow users", encryption:"Experimental encryption",
    retention:"Retention days", showSecurity:"Show encryption details", publicChat:"Public chat", restrictedGroup:"Restricted group",
    publicAnnouncement:"Public announcement", restrictedAnnouncement:"Restricted announcement", unavailable:"Chat unavailable",
    confirmUnblock:"You blocked this person. Starting a new chat removes only your block; a reverse block remains active.",
    confirmPrivateDelete:"Delete this private chat and its history for both participants?", confirmBlock:"Block this user and close the private chat?",
    confirmMessageDelete:"Delete this message for everyone?", confirmChannelDelete:"Delete this channel and all of its messages?",
    confirmRevoke:"Revoke this encrypted device?", owner:"Owner", ready:"Encrypted", experimental:"experimental", activeChannel:"Active channel",
    defaultChannel:"Default channel", cannotPost:"You cannot post in this channel.", noUsers:"No users found", noDevices:"No encrypted devices found", noChannels:"No channels found",
    messageDeleted:"Message deleted", showDeletedMessages:"Show a marker for deleted messages", userSettingsHint:"Manage the people you have blocked.",
    contactInfo:"Contact info", silence:"Silence", unsilence:"Unmute", userIdentifier:"Home Assistant user ID", moreOptions:"More options", announcements:"Announcements", showQr:"Show identity QR", scanQr:"Scan identity QR", qrCamera:"Camera", qrFile:"Choose QR image", qrPermission:"Camera permission is required to scan a QR code.", qrUnsupported:"QR scanning is unavailable in this browser. Choose an image or enter the identity manually.", qrInvalid:"No valid identity was found in that QR code.", qrDependency:"QR support is not bundled in this build yet.", federationQr:"Include federation address in identity QR codes", federationAddress:"Federation address", federationPort:"Federation port", recovery:"Encrypted recovery", createRecovery:"Create recovery code", showRecovery:"Show recovery code", restoreRecovery:"Restore from recovery code", recoveryWarning:"Save this code somewhere safe. A new device needs it; the server cannot recover it.", recoveryUnavailable:"No recovery bundle is stored yet.", recoveryInvalid:"This recovery code could not decrypt the bundle.", recoveryUpdated:"Encrypted recovery bundle updated.", recoveryCodePlaceholder:"Paste recovery code",
    resetKey:"Start with a new key", confirmResetKey:"Create a new encryption key for this chat? Older messages whose keys cannot be recovered will remain unreadable, but new messages will work.", resetError:"Could not create a new encryption key. Please try again."
  },
  de: {
    chat:"Chat", private:"Privater Chat", device:"Browser-Gerät", handle:"Identitätsnummer eingeben (zum Beispiel 48392017 oder 48392017@example.org:8123).", identityNumber:"Identitätsnummer", ownIdentity:"Deine Identität", copyIdentity:"Identität kopieren", copiedIdentity:"Kopiert", invalidIdentity:"Gib eine gültige Identitätsnummer ein: NUMMER oder NUMMER@HOST[:PORT].", federatedNotSupported:"Föderierte Identitäten werden von diesem Server noch nicht unterstützt.", send:"Senden",
    write:"Nachricht schreiben", cancel:"Abbrechen", continue:"Weiter", delete:"Löschen", deleteBoth:"Gesamten Chat löschen", block:"Blockieren",
    close:"Schließen", admin:"Administration", channels:"Kanäle", moderation:"Moderation", users:"Benutzer / Zugriff", devices:"Geräte / Verschlüsselung",
    settings:"Einstellungen", name:"Name", members:"Mitglieder", create:"Erstellen", edit:"Bearbeiten", save:"Speichern", mute:"Stummschalten", unblock:"Entsperren", blockedUsers:"Blockierte Benutzer",
    unmute:"Stummschaltung aufheben", revoke:"Widerrufen", waiting:"Warte darauf, dass ein aktives Gerät den Kanalschlüssel teilt…",
    noMessages:"Noch keine Nachrichten", encrypted:"Verschlüsselte Nachricht — Kanalschlüssel nicht verfügbar", security:"Sicherheitscode",
    deviceCount:"Geräte", enabled:"Chat aktiviert", allowUsers:"Benutzer zulassen", encryption:"Experimentelle Verschlüsselung",
    retention:"Aufbewahrungstage", showSecurity:"Verschlüsselungsdetails anzeigen", publicChat:"Öffentlicher Chat",
    restrictedGroup:"Eingeschränkte Gruppe", publicAnnouncement:"Öffentliche Ankündigung", restrictedAnnouncement:"Eingeschränkte Ankündigung",
    unavailable:"Chat nicht verfügbar", confirmUnblock:"Du hast diese Person blockiert. Ein neuer Chat entfernt nur deine Blockierung; eine Gegenblockierung bleibt aktiv.",
    confirmPrivateDelete:"Diesen privaten Chat und seinen Verlauf für beide Teilnehmer löschen?", confirmBlock:"Diesen Benutzer blockieren und den privaten Chat schließen?",
    confirmMessageDelete:"Diese Nachricht für alle löschen?", confirmChannelDelete:"Diesen Kanal und alle Nachrichten löschen?",
    confirmRevoke:"Dieses verschlüsselte Gerät widerrufen?", owner:"Besitzer", ready:"Verschlüsselt", experimental:"experimentell",
    activeChannel:"Aktiver Kanal", defaultChannel:"Standardkanal", cannotPost:"Du kannst in diesem Kanal nicht schreiben.",
    noUsers:"Keine Benutzer gefunden", noDevices:"Keine verschlüsselten Geräte gefunden", noChannels:"Keine Kanäle gefunden",
    messageDeleted:"Nachricht gelöscht", showDeletedMessages:"Markierung für gelöschte Nachrichten anzeigen", userSettingsHint:"Verwalte die von dir blockierten Benutzer.",
    contactInfo:"Kontaktinformationen", silence:"Stummschalten", unsilence:"Stummschaltung aufheben", userIdentifier:"Home-Assistant-Benutzer-ID", moreOptions:"Weitere Optionen", announcements:"Ankündigungen", showQr:"Identitäts-QR anzeigen", scanQr:"Identitäts-QR scannen", qrCamera:"Kamera", qrFile:"QR-Bild auswählen", qrPermission:"Zum Scannen eines QR-Codes ist eine Kameraberechtigung erforderlich.", qrUnsupported:"QR-Scannen ist in diesem Browser nicht verfügbar. Wähle ein Bild oder gib die Identität manuell ein.", qrInvalid:"In diesem QR-Code wurde keine gültige Identität gefunden.", qrDependency:"QR-Unterstützung ist in diesem Build noch nicht gebündelt.", federationQr:"Föderationsadresse in Identitäts-QR-Codes einschließen", federationAddress:"Föderationsadresse", federationPort:"Föderationsport", recovery:"Verschlüsselte Wiederherstellung", createRecovery:"Wiederherstellungscode erstellen", showRecovery:"Wiederherstellungscode anzeigen", restoreRecovery:"Mit Wiederherstellungscode wiederherstellen", recoveryWarning:"Bewahre diesen Code sicher auf. Ein neues Gerät benötigt ihn; der Server kann ihn nicht wiederherstellen.", recoveryUnavailable:"Noch kein Wiederherstellungsbundle gespeichert.", recoveryInvalid:"Dieser Wiederherstellungscode konnte das Bundle nicht entschlüsseln.", recoveryUpdated:"Verschlüsseltes Wiederherstellungsbundle aktualisiert.", recoveryCodePlaceholder:"Wiederherstellungscode einfügen",
    resetKey:"Mit neuem Schlüssel fortfahren", confirmResetKey:"Einen neuen Verschlüsselungsschlüssel für diesen Chat erstellen? Ältere Nachrichten ohne wiederherstellbaren Schlüssel bleiben unlesbar, aber neue Nachrichten funktionieren wieder.", resetError:"Der neue Verschlüsselungsschlüssel konnte nicht erstellt werden. Bitte versuche es erneut."
  }
};

function migratedStorageEntry(key, value) {
  if (key === "identity") return {primary:"device", legacy:"legacy-device", value:{...value, id:value.id || value.deviceId}};
  if (typeof key === "string" && key.startsWith("channel:")) {
    const suffix=key.slice("channel:".length);
    return {primary:`key:${suffix}`, legacy:`legacy-key:${suffix}`, value};
  }
  return null;
}

function migrateStorage(transaction, sourceName, target) {
  const cursorRequest = transaction.objectStore(sourceName).openCursor();
  cursorRequest.onsuccess = () => {
    const cursor = cursorRequest.result; if (!cursor) return;
    const migrated = migratedStorageEntry(cursor.key, cursor.value);
    if (!migrated) { cursor.continue(); return; }
    const existingRequest=target.get(migrated.primary);
    existingRequest.onsuccess=() => {
      target.put(migrated.value, existingRequest.result === undefined ? migrated.primary : migrated.legacy);
      cursor.continue();
    };
  };
}

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("ha-chat-device-v1", 3);
    request.onupgradeneeded = () => {
      const database=request.result; const transaction=request.transaction;
      const target=database.objectStoreNames.contains("values") ? transaction.objectStore("values") : database.createObjectStore("values");
      if (database.objectStoreNames.contains("v")) migrateStorage(transaction,"v",target);
      migrateStorage(transaction,"values",target);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function dbGet(key) {
  const database = await openDatabase();
  return new Promise((resolve, reject) => {
    const request = database.transaction("values").objectStore("values").get(key);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function dbPut(key, value) {
  const database = await openDatabase();
  return new Promise((resolve, reject) => {
    const request = database.transaction("values", "readwrite").objectStore("values").put(value, key);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

async function dbDelete(key) {
  const database = await openDatabase();
  return new Promise((resolve, reject) => {
    const request = database.transaction("values", "readwrite").objectStore("values").delete(key);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

// IndexedDB has no portable startsWith query, so enumerate the small local key
// store and filter in memory. This never uploads the keys themselves.
async function dbEntriesWithPrefix(prefix) {
  const database = await openDatabase();
  return new Promise((resolve, reject) => {
    const result = [];
    const request = database.transaction("values").objectStore("values").openCursor();
    request.onsuccess = () => { const cursor = request.result; if (!cursor) { resolve(result); return; } if (String(cursor.key).startsWith(prefix)) result.push([String(cursor.key), cursor.value]); cursor.continue(); };
    request.onerror = () => reject(request.error);
  });
}

const base64Url = (bytes) => b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const fromBase64Url = (value) => raw(String(value).replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(String(value).length / 4) * 4, "="));

async function recoveryKeyFromCode(code, salt, iterations) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2", salt, iterations, hash:"SHA-256"}, material, {name:"AES-GCM", length:256}, false, ["encrypt", "decrypt"]);
}

async function deviceIdentity() {
  let identity = await dbGet("device");
  if (identity) return identity;
  const keys = await crypto.subtle.generateKey({name:"ECDH", namedCurve:"P-256"}, true, ["deriveKey"]);
  identity = {id:crypto.randomUUID(), keys, publicKey:await crypto.subtle.exportKey("jwk", keys.publicKey), counter:0};
  await dbPut("device", identity);
  return identity;
}

async function channelKey(channelId, epoch, create = false) {
  const storageKey = `key:${channelId}:${epoch}`;
  let key = await dbGet(storageKey);
  if (!key && create) {
    key = await crypto.subtle.generateKey({name:"AES-GCM", length:256}, true, ["encrypt", "decrypt"]);
    await dbPut(storageKey, key);
  }
  return key;
}

async function channelKeyCommitment(key) {
  if (!key) return null;
  return b64(await crypto.subtle.digest("SHA-256", await crypto.subtle.exportKey("raw", key)));
}

async function wrapChannelKey(key, target) {
  const identity = await deviceIdentity();
  const publicKey = await crypto.subtle.importKey("jwk", JSON.parse(target.public_key), {name:"ECDH", namedCurve:"P-256"}, false, []);
  const wrappingKey = await crypto.subtle.deriveKey({name:"ECDH", public:publicKey}, identity.keys.privateKey, {name:"AES-GCM", length:256}, false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({name:"AES-GCM", iv:nonce}, wrappingKey, await crypto.subtle.exportKey("raw", key));
  return JSON.stringify({nonce:b64(nonce), ciphertext:b64(ciphertext), sender_public:identity.publicKey, sender_device_id:identity.id});
}

async function unwrapChannelKey(channelId, offer) {
  const identity = await deviceIdentity();
  const wrapped = JSON.parse(offer.wrapped_key);
  const publicKey = await crypto.subtle.importKey("jwk", wrapped.sender_public, {name:"ECDH", namedCurve:"P-256"}, false, []);
  const wrappingKey = await crypto.subtle.deriveKey({name:"ECDH", public:publicKey}, identity.keys.privateKey, {name:"AES-GCM", length:256}, false, ["decrypt"]);
  const keyBytes = await crypto.subtle.decrypt({name:"AES-GCM", iv:raw(wrapped.nonce)}, wrappingKey, raw(wrapped.ciphertext));
  const key = await crypto.subtle.importKey("raw", keyBytes, {name:"AES-GCM"}, true, ["encrypt", "decrypt"]);
  await dbPut(`key:${channelId}:${offer.key_id.split(":").pop()}`, key);
}

async function encryptMessage(channelId, epoch, text) {
  const identity = await deviceIdentity();
  const key = await channelKey(channelId, epoch, true);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const additionalData = encoder.encode(channelId);
  identity.counter += 1;
  await dbPut("device", identity);
  const ciphertext = await crypto.subtle.encrypt({name:"AES-GCM", iv:nonce, additionalData}, key, encoder.encode(text));
  const commitment=await channelKeyCommitment(key);
  return {ciphertext:b64(ciphertext), envelope:{version:"ha-chat/1", device_id:identity.id, counter:identity.counter, nonce:b64(nonce), key_id:`${channelId}:${epoch}`, key_commitment:commitment, aad:b64(additionalData)}};
}

async function decryptMessage(message) {
  const epoch = message.envelope.key_id.split(":").pop();
  const keys=[await channelKey(message.channel_id, epoch),await dbGet(`legacy-key:${message.channel_id}:${epoch}`)].filter(Boolean);
  for (const key of keys) try {
    return decoder.decode(await crypto.subtle.decrypt({name:"AES-GCM", iv:raw(message.envelope.nonce), additionalData:raw(message.envelope.aad)}, key, raw(message.ciphertext)));
  } catch { /* Try the key retained from the previous storage layout. */ }
  return null;
}

async function keySecurityCode(key) {
  if (!key) return null;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", await crypto.subtle.exportKey("raw", key)));
  return [...digest.slice(0, 12)].map((value) => value.toString(16).padStart(2, "0")).join("").match(/.{1,4}/g).join(" ");
}

class HomeAssistantChatPanel extends HTMLElement {
  set hass(value) { this._hass = value; this._disconnected = false; if (!this._ready && !this._initializing) this.initialize(); }
  set panel(value) { this._panel = value; }
  set narrow(value) { this._narrow = value; }
  get language() { const language=String(globalThis.navigator?.languages?.[0] || globalThis.navigator?.language || this._hass?.language || this._hass?.locale?.language || "en").split(/[-_]/)[0].toLowerCase(); return STRINGS[language] ? language : "en"; }
  get text() { return STRINGS[this.language]; }
  ws(message) { return this._hass.callWS(message); }

  async initialize() {
    if (this._initializing || this._disconnected || !this._hass) return;
    this._initializing = true; this._error = ""; this._channels ||= []; this._messages ||= []; this._active ||= "public"; this._keyRequests ||= new Set(); this.setupViewport(); this.render();
    try {
      // Core state is deliberately independent from browser crypto. A crypto
      // failure must never hide channels, admin controls, or loaded messages.
      await this.refreshState();
      this._coreReady = true; this._ready = true; this._retryAttempt = 0; this._initializing = false; if (this._retryTimer) { clearTimeout(this._retryTimer); this._retryTimer = null; }
      if (this._disconnected) return;
      if (typeof this._unsubscribe !== "function") {
        try { this._unsubscribe = await this._hass.connection.subscribeMessage((event) => this.handleEvent(event), {type:"home_assistant_chat/subscribe"}); }
        catch (error) { this._error = `${this.text.unavailable} (${this.sanitizeError(error)})`; this.render(); }
      }
      this.startEncryption();
    } catch (error) {
      this._coreReady = false; this._ready = false; this._initializing = false; this._error = `${this.text.unavailable} (${this.sanitizeError(error)})`; this.render();
      this.scheduleInitializationRetry();
    }
  }

  sanitizeError(error) {
    const value = String(error?.code || error?.message || "unknown").replace(/[^A-Za-z0-9_.:-]/g, "").slice(0, 48);
    return value || "unknown";
  }

  async startEncryption() {
    if (this._encryptionInitializing || this._disconnected || !this._coreReady || !this._hass) return;
    this._encryptionInitializing = true; this._encryptionError = ""; this.render();
    try {
      const identity = await deviceIdentity();
      await this.ws({type:"home_assistant_chat/device/register", device_id:identity.id, public_key:JSON.stringify(identity.publicKey), label:this.text.device});
      await this.refreshState(); await this.claimOffers();
      try { if (await dbGet("recovery-code")) await this.updateRecoveryBundle(); } catch { /* Optional recovery sync must never block the chat UI. */ }
      await this.selectChannel(this._active);
      if (this._keySyncTimer) clearInterval(this._keySyncTimer); this._keySyncTimer = setInterval(() => this.syncKeyRequests().catch(() => {}), 10000);
      this._encryptionInitializing = false; this._encryptionRetryAttempt = 0; if (this._encryptionRetryTimer) { clearTimeout(this._encryptionRetryTimer); this._encryptionRetryTimer = null; }
    } catch (error) {
      this._encryptionInitializing = false; this._encryptionError = `${this.text.unavailable} (${this.sanitizeError(error)})`; this.render(); this.scheduleEncryptionRetry();
    }
  }

  scheduleInitializationRetry() {
    if (this._retryTimer || this._disconnected || !this._hass) return;
    const delays = [500, 1000, 2000, 5000, 10000, 30000]; const delay = delays[Math.min(this._retryAttempt || 0, delays.length - 1)]; this._retryAttempt = Math.min((this._retryAttempt || 0) + 1, delays.length - 1);
    this._retryTimer = setTimeout(() => { this._retryTimer = null; this.initialize(); }, delay);
  }

  scheduleEncryptionRetry() {
    if (this._encryptionRetryTimer || this._disconnected || !this._coreReady || !this._hass) return;
    const delays = [1000, 2000, 5000, 10000, 30000]; const delay = delays[Math.min(this._encryptionRetryAttempt || 0, delays.length - 1)]; this._encryptionRetryAttempt = Math.min((this._encryptionRetryAttempt || 0) + 1, delays.length - 1);
    this._encryptionRetryTimer = setTimeout(() => { this._encryptionRetryTimer = null; this.startEncryption(); }, delay);
  }

  disconnectedCallback() { this._disconnected = true; this.stopQrScanner(); this.teardownViewport(); if (this._keySyncTimer) { clearInterval(this._keySyncTimer); this._keySyncTimer = null; } if (this._retryTimer) { clearTimeout(this._retryTimer); this._retryTimer = null; } if (this._encryptionRetryTimer) { clearTimeout(this._encryptionRetryTimer); this._encryptionRetryTimer = null; } if (typeof this._unsubscribe === "function") this._unsubscribe(); this._unsubscribe = null; this._ready = false; this._coreReady = false; }

  updateViewportHeight() { const viewport=window.visualViewport; const height=viewport?.height || window.innerHeight; this.style.setProperty("--ha-chat-vh", `${height}px`); }
  setupViewport() { if (this._viewportHandler) return; this._viewportHandler=()=>this.updateViewportHeight(); this.updateViewportHeight(); window.addEventListener("resize",this._viewportHandler,{passive:true}); window.visualViewport?.addEventListener("resize",this._viewportHandler,{passive:true}); window.visualViewport?.addEventListener("scroll",this._viewportHandler,{passive:true}); }
  teardownViewport() { if (!this._viewportHandler) return; window.removeEventListener("resize",this._viewportHandler); window.visualViewport?.removeEventListener("resize",this._viewportHandler); window.visualViewport?.removeEventListener("scroll",this._viewportHandler); this._viewportHandler=null; }

  async refreshState() {
    this._state = await this.ws({type:"home_assistant_chat/state"});
    this._channels = this._state.channels || []; this._messages = this._state.messages || [];
    if (!this._channels.some((channel) => channel.id === this._active)) this._active = this._channels[0]?.id || null;
    this._plaintext ||= new Map(); const liveIds=new Set(this._messages.map((message) => message.id));
    for (const id of this._plaintext.keys()) if (!liveIds.has(id)) this._plaintext.delete(id);
    await Promise.all(this._messages.filter((message) => message.channel_id === this._active && !message.deleted && !this._plaintext.has(message.id)).map(async (message) => { const value=await decryptMessage(message); if (value !== null) this._plaintext.set(message.id,value); }));
    this.render();
  }

  async handleEvent(event) {
    if (event.event === "key_request" && event.request?.channel_id) {
      const channel = this._channels.find((item) => item.id === event.request.channel_id);
      if (channel) await this.shareKey(channel.id, channel.key_epoch || 1);
    }
    if (event.event === "key_offer") { const imported = await this.claimOffers(); if (imported) await this.updateRecoveryBundle(); }
    await this.refreshState();
    if (this._active) await this.updateKeyState(this._active);
  }

  async claimOffers(states = null) {
    const identity = await deviceIdentity();
    let imported = false;
    for (const channel of this._channels) {
      try {
        const state = states?.get(channel.id) || await this.ws({type:"home_assistant_chat/key/state", channel_id:channel.id});
        for (const group of Object.values(state.offers || {})) for (const offer of Object.values(group)) if (offer.device_id === identity.id) {
          const epoch = offer.key_id.split(":").pop(); const storageKey=`key:${channel.id}:${epoch}`; const existing=await channelKey(channel.id,epoch); const expected=state.commitments?.[offer.key_id] || null;
          if (expected && offer.key_commitment && offer.key_commitment !== expected) continue;
          if (existing && (!expected || await channelKeyCommitment(existing) === expected)) continue;
          if (existing) await dbDelete(storageKey);
          await unwrapChannelKey(channel.id, offer);
          const importedKey=await channelKey(channel.id,epoch);
          if (expected && await channelKeyCommitment(importedKey) !== expected) { await dbDelete(storageKey); continue; }
          imported = true; this._keyRequests.delete(`${channel.id}:${epoch}`);
        }
      } catch { /* inaccessible channels are omitted */ }
    }
    return imported;
  }

  async syncKeyRequests() {
    if (this._disconnected || !this._coreReady) return;
    const states=new Map();
    for (const channel of this._channels) try { states.set(channel.id,await this.ws({type:"home_assistant_chat/key/state",channel_id:channel.id})); } catch { /* A stale channel must not stop synchronization. */ }
    await this.claimOffers(states);
    for (const channel of this._channels) {
      const epoch=channel.key_epoch || 1; const state=states.get(channel.id); if (!state) continue; const key=await channelKey(channel.id,epoch);
      if (key && state.pending_requests?.length) await this.shareKey(channel.id,epoch);
      if (channel.id === this._active && !key && this._messages.some((message) => message.channel_id === channel.id)) { this._keyRequests.delete(`${channel.id}:${epoch}`); await this.updateKeyState(channel.id); }
    }
  }

  async updateKeyState(channelId) {
    const channel = this._channels.find((item) => item.id === channelId); if (!channel) return;
    try {
      const imported = await this.claimOffers(); if (imported) await this.updateRecoveryBundle(); this._keyState = await this.ws({type:"home_assistant_chat/key/state", channel_id:channelId});
      const epoch=channel.key_epoch || 1; let key = await channelKey(channelId,epoch); const expected=this._keyState?.commitment || null;
      if (key && expected && await channelKeyCommitment(key) !== expected) { await dbDelete(`key:${channelId}:${epoch}`); key=null; }
      this._securityCode = await keySecurityCode(key); const hasMessages = this._messages.some((message) => message.channel_id === channelId);
      this._waiting = !key && hasMessages;
      const requestKey = `${channelId}:${channel.key_epoch || 1}`;
      if (this._waiting && !this._keyRequests.has(requestKey)) { this._keyRequests.add(requestKey); try { const identity = await deviceIdentity(); await this.ws({type:"home_assistant_chat/key/request", channel_id:channelId, device_id:identity.id}); } catch (error) { this._keyRequests.delete(requestKey); throw error; } }
    } catch { this._waiting = true; }
    this.render();
  }

  async selectChannel(channelId) {
    this._active = channelId; this._error = ""; this._waiting = false; this.render(); await this.updateKeyState(channelId);
    const latest = this._messages.filter((message) => message.channel_id === channelId).at(-1);
    if (latest) this.ws({type:"home_assistant_chat/seen", channel_id:channelId, message_id:latest.id}).catch(() => {});
  }

  async shareKey(channelId, epoch) {
    const key = await channelKey(channelId, epoch); if (!key) return;
    try {
      const identity = await deviceIdentity(); const commitment=await channelKeyCommitment(key);
      for (const target of await this.ws({type:"home_assistant_chat/key/devices", channel_id:channelId})) {
        if (target.id === identity.id) continue;
        try { await this.ws({type:"home_assistant_chat/key/offer", channel_id:channelId, device_id:target.id, key_id:`${channelId}:${epoch}`, key_commitment:commitment, wrapped_key:await wrapChannelKey(key, target)}); }
        catch { /* One stale device must not prevent sharing with the others. */ }
      }
    } catch { /* inaccessible channels are skipped */ }
  }

  resetEncryption(channel) {
    if (!channel) return;
    this.confirmDialog(this.text.confirmResetKey, this.text.resetKey, async () => {
      try {
        const identity=await deviceIdentity();
        const result=await this.ws({type:"home_assistant_chat/key/reset",channel_id:channel.id,device_id:identity.id,expected_epoch:channel.key_epoch || 1});
        const key=await channelKey(channel.id,result.key_epoch,true);
        this._keyRequests.delete(`${channel.id}:${channel.key_epoch || 1}`); await this.refreshState(); await this.shareKey(channel.id,result.key_epoch); await this.updateRecoveryBundle(); this._securityCode=await keySecurityCode(key); this._waiting=false; this.render();
      } catch { this._error = this.text.resetError; this.render(); }
    });
  }

  dialog(title, body, actions) {
    const backdrop = document.createElement("div"); backdrop.className = "modal";
    backdrop.innerHTML = `<div class="dialog" role="dialog" aria-modal="true"><h3>${esc(title)}</h3>${body}<div class="actions">${actions}</div></div>`;
    backdrop.addEventListener("click", (event) => { if (event.target === backdrop) backdrop.remove(); }); this.shadowRoot.append(backdrop); return backdrop;
  }

  confirmDialog(message, yesLabel, action) {
    const dialog = this.dialog(this.text.continue, `<p>${esc(message)}</p>`, `<button class="button cancel">${this.text.cancel}</button><button class="button yes">${esc(yesLabel)}</button>`);
    dialog.querySelector(".cancel").addEventListener("click", () => dialog.remove());
    dialog.querySelector(".yes").addEventListener("click", async () => { dialog.remove(); await action(); });
  }

  cannotPost(channel) { return Boolean(this._state?.is_muted || this._waiting || (channel?.kind === "announcement" && !this._state?.is_admin)); }

  draftKey(channelId) { return `draft:${this._state?.server_id || this._state?.serverId || "local"}:${this._state?.user_id || "unknown"}:${channelId}`; }
  queueDraftSave(channelId, value) {
    if (!channelId) return; this._draftValues ||= new Map(); const key=this.draftKey(channelId); this._draftValues.set(key,value);
    (value ? dbPut(key,value) : dbDelete(key)).catch(() => { /* Draft persistence is optional. */ });
  }
  async restoreDraft(channelId) {
    if (!channelId) return;
    try { this._draftValues ||= new Map(); const key=this.draftKey(channelId); const value=this._draftValues.has(key) ? this._draftValues.get(key) : await dbGet(key); this._draftValues.set(key,value || ""); const input = this.shadowRoot.querySelector("#message-input"); if (input && this._active === channelId && !input.value && value) input.value = value; } catch { /* Draft persistence is optional. */ }
  }

  async sendMessage(event) {
    event.preventDefault(); const input = this.shadowRoot.querySelector("#message-input"); const channel = this._channels.find((item) => item.id === this._active);
    const value = input.value.trim(); if (!channel || !value || this.cannotPost(channel)) return; const epoch = channel.key_epoch || 1;
    try {
      const state=await this.ws({type:"home_assistant_chat/key/state",channel_id:channel.id}); let localKey=await channelKey(channel.id,epoch);
      if (localKey && state.commitment && await channelKeyCommitment(localKey) !== state.commitment) { await dbDelete(`key:${channel.id}:${epoch}`); localKey=null; }
      if (!localKey && this._messages.some((message) => message.channel_id === channel.id)) { this._waiting = true; await this.updateKeyState(channel.id); return; }
      const encrypted = await encryptMessage(channel.id, epoch, value);
      const sent=await this.ws({type:"home_assistant_chat/send", channel_id:channel.id, ...encrypted}); if (sent?.message?.id) { this._plaintext ||= new Map(); this._plaintext.set(sent.message.id,value); } await this.shareKey(channel.id, epoch); await this.updateRecoveryBundle(); this._draftValues?.delete(this.draftKey(channel.id)); await dbDelete(this.draftKey(channel.id)); const currentInput=this.shadowRoot.querySelector("#message-input"); if (currentInput) currentInput.value="";
    } catch (error) { if (String(error?.code || error?.message).includes("key_commitment_conflict")) { await this.refreshState(); this._waiting=true; await this.updateKeyState(channel.id); } else { this._error = this.text.unavailable; this.render(); } }
  }

  identityValue() { return String(this._state?.identity || ""); }

  identityMarkup() {
    const identity = this.identityValue();
    const qrIdentity = String(this._state?.identity_address || identity);
    return `<div class="identity-card"><span>${this.text.ownIdentity}</span><code>${esc(identity || "—")}</code>${identity ? `<button class="button copy-identity" data-identity="${esc(identity)}" type="button">${this.text.copyIdentity}</button><button class="button show-identity-qr" data-identity="${esc(qrIdentity)}" type="button">${this.text.showQr}</button>` : ""}</div>`;
  }

  bindIdentityCopy(container) {
    container.querySelectorAll(".copy-identity").forEach((button) => button.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(button.dataset.identity); button.textContent = this.text.copiedIdentity; } catch { /* clipboard permission is optional */ }
    }));
  }

  stopQrScanner() {
    if (this._qrRaf) cancelAnimationFrame(this._qrRaf); this._qrRaf = null;
    if (this._qrStream) this._qrStream.getTracks().forEach((track) => track.stop()); this._qrStream = null;
  }

  async showIdentityQr(identity) {
    const dialog = this.dialog(this.text.showQr, `<p class="qr-value"><code>${esc(identity)}</code></p><div class="qr-preview" style="width:min(280px,80vw);margin:auto" aria-label="${esc(this.text.showQr)}"></div><p class="qr-note"></p>`, `<button class="button close">${this.text.close}</button>`);
    dialog.querySelector(".close").addEventListener("click", () => dialog.remove());
    dialog.addEventListener("click", (event) => { if (event.target === dialog) { this.stopQrScanner(); dialog.remove(); } });
    const preview = dialog.querySelector(".qr-preview"); const note = dialog.querySelector(".qr-note");
    try {
      // A locally vendored adapter may expose encode(text) -> data URL or SVG.
      const encoded = await globalThis.HAChatQR?.encode?.(identity);
      if (encoded) { preview.innerHTML = typeof encoded === "string" && encoded.startsWith("<") ? encoded : `<img alt="${esc(this.text.showQr)}" src="${esc(encoded)}">`; }
      else note.textContent = this.text.qrDependency;
    } catch { note.textContent = this.text.qrUnsupported; }
  }

  decodeQrSource(source) {
    const adapter = globalThis.HAChatQR;
    if (adapter?.decode) return adapter.decode(source);
    if (globalThis.BarcodeDetector) return new globalThis.BarcodeDetector({formats:["qr_code"]}).detect(source).then((items) => items[0]?.rawValue || null).catch(() => null);
    return null;
  }

  async scanQrDialog(onDecoded) {
    const dialog = this.dialog(this.text.scanQr, `<video class="qr-video" style="display:block;width:100%;max-height:55vh;object-fit:contain" autoplay playsinline muted></video><input class="qr-file" style="display:block;width:100%;margin-top:12px" type="file" accept="image/*"><p class="qr-note">${this.text.qrUnsupported}</p>`, `<button class="button cancel">${this.text.cancel}</button>`);
    const video = dialog.querySelector(".qr-video"); const note = dialog.querySelector(".qr-note"); const canvas = document.createElement("canvas"); const context = canvas.getContext("2d", {willReadFrequently:true});
    const finish = (value) => { const identity = String(value || "").trim().replace(/^ha-chat:/i, ""); if (!validIdentity(identity)) { note.textContent = this.text.qrInvalid; return false; } this.stopQrScanner(); dialog.remove(); onDecoded(identity); return true; };
    const close = () => { this.stopQrScanner(); dialog.remove(); }; dialog.querySelector(".cancel").addEventListener("click", close); dialog.addEventListener("click", (event) => { if (event.target === dialog) close(); });
    dialog.querySelector(".qr-file").addEventListener("change", async (event) => { const file = event.target.files?.[0]; if (!file) return; try { const image = await createImageBitmap(file); canvas.width=image.width; canvas.height=image.height; context.drawImage(image,0,0); if (!finish(await this.decodeQrSource(context.getImageData(0,0,canvas.width,canvas.height)))) note.textContent = this.text.qrInvalid; image.close?.(); } catch { note.textContent = this.text.qrInvalid; } });
    try {
      if (!navigator.mediaDevices?.getUserMedia) { note.textContent = this.text.qrUnsupported; return; }
      this._qrStream = await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:"environment"}}, audio:false}); video.srcObject = this._qrStream;
      const scan = async () => { if (!this._qrStream || !video.videoWidth) { this._qrRaf = requestAnimationFrame(scan); return; } canvas.width=video.videoWidth; canvas.height=video.videoHeight; context.drawImage(video,0,0); const decoded=await this.decodeQrSource(context.getImageData(0,0,canvas.width,canvas.height)); if (!finish(decoded)) this._qrRaf=requestAnimationFrame(scan); }; this._qrRaf=requestAnimationFrame(scan);
    } catch { note.textContent = this.text.qrPermission; }
  }

  async createRecoveryCode() {
    let code = await dbGet("recovery-code");
    if (!code) { code = base64Url(crypto.getRandomValues(new Uint8Array(32))); await dbPut("recovery-code", code); this._recoveryFingerprint = null; }
    await this.updateRecoveryBundle(code);
    return code;
  }

  async updateRecoveryBundle(code = null) {
    if (this._recoveryUpdating) return;
    code = code || await dbGet("recovery-code"); if (!code) return;
    this._recoveryUpdating = true;
    try {
      const entries = [];
      for (const [storageKey, key] of await dbEntriesWithPrefix("key:")) {
        try { entries.push({key_id:storageKey.slice(4), raw:base64Url(await crypto.subtle.exportKey("raw", key))}); } catch { /* non-exportable legacy keys are omitted */ }
      }
      entries.sort((a, b) => a.key_id.localeCompare(b.key_id));
      const fingerprintInput = encoder.encode(entries.map((item) => `${item.key_id}\n${item.raw}`).join("\n"));
      const fingerprint = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", fingerprintInput)));
      if (this._recoveryFingerprint === fingerprint) return;
      const payload = encoder.encode(JSON.stringify({version:1, keys:entries}));
      const salt = crypto.getRandomValues(new Uint8Array(16)); const nonce = crypto.getRandomValues(new Uint8Array(12)); const iterations = 210000;
      const wrappingKey = await recoveryKeyFromCode(code, salt, iterations);
      const ciphertext = await crypto.subtle.encrypt({name:"AES-GCM", iv:nonce}, wrappingKey, payload);
      await this.ws({type:"home_assistant_chat/recovery/set", bundle:{version:1, ciphertext:b64(ciphertext), salt:b64(salt), nonce:b64(nonce), kdf:{name:"PBKDF2", hash:"SHA-256", iterations}}});
      this._recoveryFingerprint = fingerprint;
    } finally { this._recoveryUpdating = false; }
  }

  async restoreRecovery(code) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(String(code || ""))) throw new Error("recovery_invalid");
    const bundle = await this.ws({type:"home_assistant_chat/recovery/get"});
    if (!bundle) throw new Error("recovery_missing");
    const iterations = Number(bundle.kdf?.iterations); let salt, nonce, ciphertext;
    try { salt = raw(bundle.salt); nonce = raw(bundle.nonce); ciphertext = raw(bundle.ciphertext); } catch { throw new Error("recovery_invalid"); }
    if (bundle.version !== 1 || bundle.kdf?.name !== "PBKDF2" || bundle.kdf?.hash !== "SHA-256" || !Number.isSafeInteger(iterations) || iterations < 200000 || iterations > 1000000 || salt.length < 16 || nonce.length !== 12 || !ciphertext.length) throw new Error("recovery_invalid");
    const wrappingKey = await recoveryKeyFromCode(code, salt, iterations);
    let decoded;
    try { decoded = JSON.parse(decoder.decode(await crypto.subtle.decrypt({name:"AES-GCM", iv:nonce}, wrappingKey, ciphertext))); } catch { throw new Error("recovery_invalid"); }
    if (decoded.version !== 1 || !Array.isArray(decoded.keys)) throw new Error("recovery_invalid");
    for (const item of decoded.keys) {
      if (typeof item?.key_id !== "string" || item.key_id.length > 200 || !/^[^:]{1,128}:\d{1,12}$/.test(item.key_id) || typeof item.raw !== "string" || !/^[A-Za-z0-9_-]+$/.test(item.raw)) throw new Error("recovery_invalid");
      let keyBytes; try { keyBytes = fromBase64Url(item.raw); } catch { throw new Error("recovery_invalid"); }
      if (keyBytes.length !== 32) throw new Error("recovery_invalid");
      const key = await crypto.subtle.importKey("raw", keyBytes, {name:"AES-GCM"}, true, ["encrypt", "decrypt"]);
      await dbPut(`key:${item.key_id}`, key);
    }
    await dbPut("recovery-code", code);
    this._recoveryFingerprint = null; await this.refreshState(); await this.claimOffers(); if (this._active) await this.updateKeyState(this._active);
  }

  recoveryMarkup() {
    return `<section class="recovery-section"><h4>${this.text.recovery}</h4><p>${this.text.recoveryWarning}</p><div class="actions recovery-actions" style="flex-wrap:wrap"><button class="button create-recovery">${this.text.createRecovery}</button><button class="button restore-recovery">${this.text.restoreRecovery}</button></div></section>`;
  }

  bindRecoveryActions(container) {
    container.querySelector(".create-recovery")?.addEventListener("click", async (event) => {
      const code = await this.createRecoveryCode(); const dialog = this.dialog(this.text.showRecovery, `<p>${this.text.recoveryWarning}</p><input class="recovery-code" style="width:100%;max-width:100%;font-family:monospace" readonly value="${esc(code)}">`, `<button class="button copy-recovery">${this.text.copyIdentity}</button><button class="button close">${this.text.close}</button>`);
      dialog.querySelector(".copy-recovery").addEventListener("click", async () => { try { await navigator.clipboard.writeText(code); } catch {} }); dialog.querySelector(".close").addEventListener("click", () => dialog.remove());
    });
    container.querySelector(".restore-recovery")?.addEventListener("click", () => {
      const dialog = this.dialog(this.text.restoreRecovery, `<p>${this.text.recoveryWarning}</p><input class="recovery-input" autocomplete="off" placeholder="${this.text.recoveryCodePlaceholder}"><p class="recovery-error" role="alert"></p>`, `<button class="button cancel">${this.text.cancel}</button><button class="button restore">${this.text.restoreRecovery}</button>`);
      dialog.querySelector(".cancel").addEventListener("click", () => dialog.remove()); dialog.querySelector(".restore").addEventListener("click", async () => { try { await this.restoreRecovery(dialog.querySelector(".recovery-input").value.trim()); dialog.remove(); } catch { dialog.querySelector(".recovery-error").textContent = this.text.recoveryInvalid; } });
    });
  }

  privateDialog() {
    const dialog = this.dialog(this.text.private, `<label>${this.text.identityNumber}<input id="private-handle" autocomplete="off" inputmode="text" placeholder="48392017 or 48392017@example.org:8123"></label><p>${this.text.handle}</p><p class="identity-error" role="alert"></p>`, `<button class="button scan-identity">${this.text.scanQr}</button><button class="button cancel">${this.text.cancel}</button><button class="button start">${this.text.continue}</button>`);
    dialog.querySelector(".cancel").addEventListener("click", () => dialog.remove());
    dialog.querySelector(".scan-identity").addEventListener("click", () => this.scanQrDialog((identity) => { dialog.querySelector("#private-handle").value = identity; }));
    dialog.querySelector(".start").addEventListener("click", async () => {
      const handle = dialog.querySelector("#private-handle").value.trim();
      if (!validIdentity(handle)) { dialog.querySelector(".identity-error").textContent = this.text.invalidIdentity; return; }
      try { const result = await this.ws({type:"home_assistant_chat/private", handle, confirm_unblock:false}); dialog.remove(); await this.refreshState(); await this.selectChannel(result.channel.id); }
      catch (error) {
        if (String(error?.code || error?.message).includes("confirm_unblock")) this.confirmDialog(this.text.confirmUnblock, this.text.continue, async () => { const result = await this.ws({type:"home_assistant_chat/private", handle, confirm_unblock:true}); await this.refreshState(); await this.selectChannel(result.channel.id); });
        else { dialog.remove(); this._error = String(error?.code || error?.message).includes("federated_identity_not_supported") ? this.text.federatedNotSupported : String(error?.code || error?.message).includes("invalid_identity") ? this.text.invalidIdentity : this.text.unavailable; this.render(); }
      }
    });
  }

  blockPrivate(channel) {
    if (!channel?.peer?.id) return;
    this.confirmDialog(this.text.confirmBlock, this.text.block, async () => { await this.ws({type:"home_assistant_chat/user/block", user_id:channel.peer.id}); await this.refreshState(); });
  }

  deletePrivate(channel) {
    this.confirmDialog(this.text.confirmPrivateDelete, this.text.deleteBoth, async () => { await this.ws({type:"home_assistant_chat/private/delete", channel_id:channel.id, confirm:true}); await this.refreshState(); });
  }

  privateInfoDialog(channel) {
    if (!channel?.peer) return;
    const identity = String(channel.peer.identity || ""); const qrIdentity = String(channel.peer.identity_address || identity);
    const dialog = this.dialog(this.text.contactInfo, `<div class="row"><span>${this.text.name}</span><strong>${esc(channel.peer.name)}</strong></div><div class="row"><span>${this.text.identityNumber}</span><code>${esc(identity || "—")}</code></div>`, `${identity ? `<button class="button show-peer-qr">${this.text.showQr}</button>` : ""}<button class="button close">${this.text.close}</button>`);
    dialog.querySelector(".show-peer-qr")?.addEventListener("click", () => this.showIdentityQr(qrIdentity));
    dialog.querySelector(".close").addEventListener("click", () => dialog.remove());
  }

  async togglePrivateSilence(channel) {
    await this.ws({type:"home_assistant_chat/private/silence", channel_id:channel.id, silenced:!channel.silenced}); await this.refreshState();
  }

  privateMenu(channel, placement="header") {
    if (channel?.kind !== "private") return "";
    const text=this.text; const channelId=esc(channel.id);
    return `<details class="private-menu ${placement === "sidebar" ? "sidebar-private-menu" : ""}"><summary aria-label="${esc(text.moreOptions)}" title="${esc(text.moreOptions)}"><ha-icon icon="mdi:dots-vertical" aria-hidden="true"></ha-icon></summary><div class="private-menu-popover"><button class="button private-info" data-channel-id="${channelId}">${text.contactInfo}</button><button class="button silence-private" data-channel-id="${channelId}">${channel.silenced ? text.unsilence : text.silence}</button><button class="button danger block-private" data-channel-id="${channelId}">${text.block}</button><button class="button danger delete-private" data-channel-id="${channelId}">${text.deleteBoth}</button></div></details>`;
  }

  channelName(channel) {
    if (channel?.id === "public") return this.text.publicChat;
    if (channel?.id === "announcements") return this.text.announcements;
    if (channel?.kind === "private") return channel.peer?.name || this.text.private;
    return channel?.name || this.text.chat;
  }

  channelKind(channel) {
    if (channel.kind === "announcement") return channel.restricted ? "announcement_restricted" : "announcement_public";
    if (channel.kind === "group" || channel.restricted) return "group";
    return "public";
  }

  channelEditor(channel, users, onSaved) {
    const selected = new Set(channel?.members || []); const kind = channel ? this.channelKind(channel) : "public"; const locked = ["public", "announcements"].includes(channel?.id);
    const dialog = this.dialog(channel ? this.text.edit : this.text.create,
      `<label>${this.text.name}<input id="channel-name" value="${esc(channel?.name || "")}"></label><label>${this.text.channels}<select id="channel-kind" ${locked ? "disabled" : ""}>
       <option value="public" ${kind === "public" ? "selected" : ""}>${this.text.publicChat}</option><option value="group" ${kind === "group" ? "selected" : ""}>${this.text.restrictedGroup}</option>
       <option value="announcement_public" ${kind === "announcement_public" ? "selected" : ""}>${this.text.publicAnnouncement}</option><option value="announcement_restricted" ${kind === "announcement_restricted" ? "selected" : ""}>${this.text.restrictedAnnouncement}</option></select></label>
       <label>${this.text.members}<select id="channel-members" multiple ${locked ? "disabled" : ""}>${users.map((user) => `<option value="${esc(user.id)}" ${selected.has(user.id) ? "selected" : ""}>${esc(user.name)}</option>`).join("")}</select></label>`,
      `<button class="button cancel">${this.text.cancel}</button><button class="button save">${this.text.save}</button>`);
    dialog.querySelector(".cancel").addEventListener("click", () => dialog.remove());
    dialog.querySelector(".save").addEventListener("click", async () => {
      const choice = dialog.querySelector("#channel-kind").value;
      const payload = {name:dialog.querySelector("#channel-name").value.trim(), kind:choice.startsWith("announcement") ? "announcement" : choice,
        restricted:choice === "group" || choice === "announcement_restricted", members:[...dialog.querySelector("#channel-members").selectedOptions].map((option) => option.value)};
      if (channel) await this.ws({type:"home_assistant_chat/channel/edit", channel_id:channel.id, name:payload.name, kind:payload.kind, restricted:payload.restricted, members:payload.members});
      else await this.ws({type:"home_assistant_chat/channel/create", ...payload});
      dialog.remove(); await this.refreshState(); await onSaved();
    });
  }

  blockedUsersMarkup(blocked) {
    return `<h4>${this.text.blockedUsers}</h4>${blocked.length ? blocked.map((user) => `<div class="row"><span>${esc(user.name)}</span><button class="button unblock-user" data-id="${esc(user.id)}">${this.text.unblock}</button></div>`).join("") : `<p>${this.text.noUsers}</p>`}`;
  }

  bindUnblockActions(container, onUpdated) {
    container.querySelectorAll(".unblock-user").forEach((button) => button.addEventListener("click", async () => {
      await this.ws({type:"home_assistant_chat/user/unblock", user_id:button.dataset.id}); await onUpdated();
    }));
  }

  async userSettingsDialog() {
    const blocked = await this.ws({type:"home_assistant_chat/user/blocked"});
    const body = `${this.identityMarkup()}${this.recoveryMarkup()}<p>${this.text.userSettingsHint}</p>${this.blockedUsersMarkup(blocked)}`;
    const dialog = this.dialog(this.text.settings, body, `<button class="button close">${this.text.close}</button>`);
    dialog.querySelector(".close").addEventListener("click", () => dialog.remove());
    this.bindIdentityCopy(dialog);
    dialog.querySelectorAll(".show-identity-qr").forEach((button) => button.addEventListener("click", () => this.showIdentityQr(button.dataset.identity)));
    this.bindRecoveryActions(dialog);
    this.bindUnblockActions(dialog, async () => { dialog.remove(); await this.refreshState(); await this.userSettingsDialog(); });
  }

  async adminDialog() {
    let users = await this.ws({type:"home_assistant_chat/users/list"}); let devices = await this.ws({type:"home_assistant_chat/device/list"});
    const dialog = this.dialog(this.text.admin, `<nav class="tabs">${["channels","moderation","users","devices","settings"].map((tab) => `<button data-tab="${tab}">${this.text[tab]}</button>`).join("")}</nav><section id="admin-content"></section>`, `<button class="button close">${this.text.close}</button>`);
    const content = dialog.querySelector("#admin-content");
    const reload = async () => { await this.refreshState(); users = await this.ws({type:"home_assistant_chat/users/list"}); devices = await this.ws({type:"home_assistant_chat/device/list"}); };
    const show = async (tab) => {
      if (tab === "channels") {
        const managed = this._channels.filter((channel) => channel.kind !== "private");
        content.innerHTML = `<button class="button create-channel">${this.text.create}</button><div>${managed.length ? managed.map((channel) => `<div class="row"><span>${esc(this.channelName(channel))}</span><span><button class="button edit-channel" data-id="${esc(channel.id)}">${this.text.edit}</button>${["public","announcements"].includes(channel.id) ? `<small>${this.text.defaultChannel}</small>` : `<button class="button delete-channel" data-id="${esc(channel.id)}">${this.text.delete}</button>`}</span></div>`).join("") : this.text.noChannels}</div>`;
        content.querySelector(".create-channel").addEventListener("click", () => this.channelEditor(null, users, async () => show("channels")));
        content.querySelectorAll(".edit-channel").forEach((button) => button.addEventListener("click", () => this.channelEditor(this._channels.find((channel) => channel.id === button.dataset.id), users, async () => show("channels"))));
        content.querySelectorAll(".delete-channel").forEach((button) => button.addEventListener("click", () => this.confirmDialog(this.text.confirmChannelDelete, this.text.delete, async () => { await this.ws({type:"home_assistant_chat/channel/delete", channel_id:button.dataset.id}); await reload(); await show("channels"); })));
      } else if (tab === "moderation") {
        content.innerHTML = users.length ? users.map((user) => `<div class="row"><span>${esc(user.name)}</span><button class="button mute-user" data-id="${esc(user.id)}">${user.muted ? this.text.unmute : this.text.mute}</button></div>`).join("") : this.text.noUsers;
        content.querySelectorAll(".mute-user").forEach((button) => button.addEventListener("click", async () => { const user = users.find((item) => item.id === button.dataset.id); await this.ws({type:"home_assistant_chat/admin/mute", user_id:user.id, muted:!user.muted}); await reload(); await show("moderation"); }));
      } else if (tab === "users") {
        content.innerHTML = users.length ? users.map((user) => `<label class="row"><span>${esc(user.name)}</span><input class="user-access" data-id="${esc(user.id)}" type="checkbox" ${user.enabled ? "checked" : ""}></label>`).join("") : this.text.noUsers;
        content.querySelectorAll(".user-access").forEach((input) => input.addEventListener("change", async () => { await this.ws({type:"home_assistant_chat/user/access", user_id:input.dataset.id, allowed:input.checked}); await reload(); }));
      } else if (tab === "devices") {
        let keyState = null; if (this._active) try { keyState = await this.ws({type:"home_assistant_chat/key/state", channel_id:this._active}); } catch { /* inaccessible */ }
        const details = this._state.settings.show_security_details && keyState ? `<p>${this.text.activeChannel}: ${esc(this._channels.find((item) => item.id === this._active)?.name || "")} · ${this.text.deviceCount}: ${keyState.device_count} · ${this.text.security}: ${esc(this._securityCode || "—")}</p>` : `<p>${this.text.encryption} · ${this.text.experimental}</p>`;
        content.innerHTML = `${details}${devices.length ? devices.map((item) => `<div class="row"><span>${esc(item.owner_name || item.user_id)} · ${esc(item.label || item.id)}</span><button class="button revoke-device" data-id="${esc(item.id)}">${this.text.revoke}</button></div>`).join("") : this.text.noDevices}`;
        content.querySelectorAll(".revoke-device").forEach((button) => button.addEventListener("click", () => this.confirmDialog(this.text.confirmRevoke, this.text.revoke, async () => { await this.ws({type:"home_assistant_chat/device/revoke", device_id:button.dataset.id}); await reload(); await show("devices"); })));
      } else {
        const settings = this._state.settings;
        const blocked = await this.ws({type:"home_assistant_chat/user/blocked"});
        content.innerHTML = `${this.identityMarkup()}${this.recoveryMarkup()}<label class="row">${this.text.enabled}<input id="setting-enabled" type="checkbox" ${settings.enabled ? "checked" : ""}></label><label class="row">${this.text.allowUsers}<input id="setting-users" type="checkbox" ${settings.allow_users ? "checked" : ""}></label>
          <label class="row">${this.text.federationQr}<input id="setting-federation-qr" type="checkbox" ${settings.federation_qr_enabled ? "checked" : ""}></label><label>${this.text.federationAddress}<input id="setting-federation-address" value="${esc(settings.federation_address || "")}" placeholder="chat.example.org"></label><label>${this.text.federationPort}<input id="setting-federation-port" type="number" min="1" max="65535" value="${Number(settings.federation_port || 0) || ""}"></label><label class="row">${this.text.retention}<input id="setting-retention" type="number" min="0" max="3650" value="${Number(settings.retention_days || 0)}"></label><label class="row">${this.text.showSecurity}<input id="setting-security" type="checkbox" ${settings.show_security_details ? "checked" : ""}></label><label class="row">${this.text.showDeletedMessages}<input id="setting-deleted-markers" type="checkbox" ${settings.show_deleted_messages ? "checked" : ""}></label><button class="button save-settings">${this.text.save}</button>${this.blockedUsersMarkup(blocked)}`;
        this.bindIdentityCopy(content);
        content.querySelectorAll(".show-identity-qr").forEach((button) => button.addEventListener("click", () => this.showIdentityQr(button.dataset.identity)));
        this.bindRecoveryActions(content);
        content.querySelector(".save-settings").addEventListener("click", async () => { await this.ws({type:"home_assistant_chat/settings", enabled:content.querySelector("#setting-enabled").checked, allow_users:content.querySelector("#setting-users").checked, federation_qr_enabled:content.querySelector("#setting-federation-qr").checked, federation_address:content.querySelector("#setting-federation-address").value.trim(), federation_port:Number(content.querySelector("#setting-federation-port").value || 0), retention_days:Number(content.querySelector("#setting-retention").value), show_security_details:content.querySelector("#setting-security").checked, show_deleted_messages:content.querySelector("#setting-deleted-markers").checked}); await reload(); await show("settings"); });
        this.bindUnblockActions(content, async () => { await reload(); await show("settings"); });
      }
    };
    dialog.querySelector(".close").addEventListener("click", () => dialog.remove());
    dialog.querySelectorAll("[data-tab]").forEach((button) => button.addEventListener("click", () => show(button.dataset.tab))); await show("channels");
  }

  render() {
    if (!this.shadowRoot) this.attachShadow({mode:"open"}); const priorInput=this.shadowRoot.activeElement?.id === "message-input" ? {start:this.shadowRoot.activeElement.selectionStart,end:this.shadowRoot.activeElement.selectionEnd} : null; const priorMessages=this.shadowRoot.querySelector(".messages"); const priorScroll=priorMessages ? {top:priorMessages.scrollTop,atBottom:priorMessages.scrollHeight-priorMessages.scrollTop-priorMessages.clientHeight<24} : null; const text = this.text; const channels = this._channels || [];
    const current = channels.find((channel) => channel.id === this._active) || channels[0]; if (current && !this._active) this._active = current.id;
    const messages = (this._messages || []).filter((message) => message.channel_id === this._active); const readOnly = this.cannotPost(current); const peer = current?.peer;
    const security = this._state?.settings?.show_security_details && this._keyState ? `<p class="security">🔒 ${text.ready} · ${text.experimental} · ${this._keyState.device_count} ${text.deviceCount} · ${text.security}: ${esc(this._securityCode || "—")}</p>` : "";
    this.shadowRoot.innerHTML = `<style>:host{display:block;height:100dvh;min-height:0;overflow:hidden;background:var(--primary-background-color,#11151b);color:var(--primary-text-color,#e7e9ed);font:14px system-ui}*{box-sizing:border-box}main{--chat-header-height:104px;height:100%;min-height:0;display:grid;grid-template-columns:250px minmax(0,1fr);max-width:1200px;margin:auto}.side{min-height:0;border-right:1px solid var(--divider-color,#2d3540);overflow:auto}.side-top{height:var(--chat-header-height);padding:14px 12px;display:flex;align-items:center;justify-content:space-between;gap:8px;border-bottom:1px solid var(--divider-color,#2d3540)}.side-top h2{margin:0}.side-top .button{display:grid;place-items:center;width:34px;height:34px;padding:0;font-size:20px;line-height:1}.channel-list{padding:14px 12px}.channel-row{display:flex;align-items:center}.channel-row .channel{flex:1;min-width:0}.channel{display:block;width:100%;text-align:left;background:none;border:0;color:inherit;padding:10px;border-radius:8px;cursor:pointer}.active{background:var(--secondary-background-color,#2d3748)}.content{display:flex;flex-direction:column;min-width:0;min-height:0}.top{height:var(--chat-header-height);padding:14px 18px;border-bottom:1px solid var(--divider-color,#2d3540)}.topline,.header-actions,.chat-heading,.message-head,.row,.actions{display:flex;align-items:center;gap:8px}.topline,.message-head,.row{justify-content:space-between}.header-actions{justify-content:flex-end;flex-wrap:wrap}.top h3{margin:.25rem 0}.private-menu{position:relative}.private-menu summary{display:grid;place-items:center;width:34px;height:34px;border-radius:8px;cursor:pointer;list-style:none}.private-menu summary::-webkit-details-marker{display:none}.private-menu summary:hover{background:var(--secondary-background-color,#2d3748)}.private-menu-popover{position:absolute;top:38px;left:0;z-index:10;display:grid;min-width:190px;padding:6px;border:1px solid var(--divider-color,#465365);border-radius:10px;background:var(--card-background-color,#202a36);box-shadow:0 8px 24px #0007}.sidebar-private-menu .private-menu-popover{left:auto;right:0}.private-menu-popover .button{border:0;text-align:left;background:transparent}.peer-avatar{display:inline-grid;place-items:center;width:34px;height:34px;border-radius:50%;background:var(--accent-color,#03a9f4);color:#fff;font-weight:700}.security{margin:.35rem 0 0;color:var(--success-color,#58c28b);font-size:.85rem}.messages{flex:1;min-height:0;overflow:auto;padding:18px}.message{padding:10px;margin:7px 0;background:var(--card-background-color,#202a36);border-radius:10px;max-width:78%;overflow-wrap:anywhere}.message.deleted{opacity:.7;font-style:italic}.message-head{align-items:flex-start;margin-bottom:4px}.message-head small{min-width:0;padding-top:4px}.mine{margin-left:auto;background:#194e5c}.compose{display:flex;flex:0 0 auto;gap:8px;padding:12px;border-top:1px solid var(--divider-color,#2d3540)}.compose input{flex:1;min-width:0}.button,input,select{border:1px solid var(--divider-color,#465365);border-radius:8px;background:var(--card-background-color,#1b232d);color:inherit;padding:9px}.button{cursor:pointer}.button.delete-message{display:grid;place-items:center;flex:0 0 28px;width:28px;height:28px;padding:0;border:0;background:transparent}.button.delete-message:hover{background:color-mix(in srgb,var(--error-color,#ffb4ab) 12%,transparent)}.delete-message ha-icon{--mdc-icon-size:18px}.button:disabled,input:disabled{opacity:.55;cursor:not-allowed}.danger{color:var(--error-color,#ffb4ab)}.modal{position:fixed;inset:0;z-index:20;background:#0009;display:grid;place-items:center;padding:20px}.dialog{width:min(700px,100%);max-height:90vh;overflow:auto;background:var(--card-background-color,#202a36);border:1px solid var(--divider-color,#4a5868);border-radius:14px;padding:20px}.actions{justify-content:flex-end;margin-top:16px}.tabs{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:14px}.tabs button{background:var(--secondary-background-color,#2d3748);color:inherit;border:0;border-radius:7px;padding:8px;cursor:pointer}.row{padding:8px;border-bottom:1px solid var(--divider-color,#35404d)}label{display:grid;gap:5px;margin:.6rem 0}select[multiple]{min-height:9rem}@media(max-width:700px){main{--chat-header-height:auto;grid-template-columns:1fr;grid-template-rows:auto minmax(0,1fr)}.side{border-right:0}.side-top{height:auto}.channel-list{display:flex;gap:4px;overflow:auto;border-bottom:1px solid var(--divider-color,#2d3540)}.channel-row{flex:0 0 auto}.channel{white-space:nowrap;width:auto}.top{height:auto}.message{max-width:92%}.topline{align-items:flex-start;flex-direction:column}.header-actions{justify-content:flex-start}}</style><main>
      <aside class="side"><div class="side-top"><h2>${text.chat}</h2><button class="button" id="new-private" aria-label="${esc(text.private)}" title="${esc(text.private)}">+</button></div><div class="channel-list">${channels.map((channel) => `<div class="channel-row"><button class="channel ${channel.id === this._active ? "active" : ""}" data-channel="${esc(channel.id)}">${esc(this.channelName(channel))}</button>${this.privateMenu(channel,"sidebar")}</div>`).join("")}</div></aside>
      <section class="content"><header class="top"><div class="topline"><div class="chat-heading">${current?.kind === "private" && peer ? `<span class="peer-avatar">${esc(initials(peer.name))}</span><h3>${esc(peer.name)}</h3>${this.privateMenu(current)}` : `<h3>${esc(this.channelName(current))}</h3>`}</div><div class="header-actions">${(this._state?.is_admin ?? this._hass?.user?.is_admin) ? `<button class="button" id="admin">${text.admin}</button>` : `<button class="button" id="user-settings">${text.settings}</button>`}</div></div>${security}</header>
      <div class="messages">${this._waiting ? `<p>${text.waiting} <button class="button" id="reset-key">${text.resetKey}</button></p>` : ""}${this._error ? `<p>${esc(this._error)}</p>` : ""}${this._encryptionError ? `<p>${esc(this._encryptionError)}</p>` : ""}${messages.length ? messages.map((message) => `<article class="message ${message.sender_id === this._state?.user_id ? "mine" : ""} ${message.deleted ? "deleted" : ""}" data-message="${esc(message.id)}"><div class="message-head"><small>${esc(message.sender_name || "User")} · ${new Date(message.created * 1000).toLocaleString(this.language === "de" ? "de-DE" : "en-US")}</small>${!message.deleted && message.sender_id === this._state?.user_id ? `<button class="button danger delete-message" data-id="${esc(message.id)}" aria-label="${esc(text.delete)}" title="${esc(text.delete)}"><ha-icon icon="mdi:delete-outline" aria-hidden="true"></ha-icon></button>` : ""}</div><span class="body">${message.deleted ? text.messageDeleted : this._plaintext?.has(message.id) ? esc(this._plaintext.get(message.id)) : text.encrypted}</span></article>`).join("") : `<p>${text.noMessages}</p>`}</div>
      <form class="compose"><input id="message-input" maxlength="4000" autocomplete="off" placeholder="${esc(readOnly ? text.cannotPost : text.write)}" ${readOnly ? "disabled" : ""}><button class="button" ${readOnly ? "disabled" : ""}>${text.send}</button></form></section></main>`;
    if (!this.shadowRoot.querySelector("#responsive-chat-style")) { const style=document.createElement("style"); style.id="responsive-chat-style"; style.textContent="@media (max-width:700px){:host{height:100dvh;overflow:hidden}main{width:100%;height:100dvh;grid-template-columns:1fr;grid-template-rows:auto minmax(0,1fr);overflow:hidden}.side{display:grid;grid-template-columns:52px minmax(0,1fr);align-items:center;min-width:0;overflow:hidden;border-right:0;border-bottom:1px solid var(--divider-color,#2d3540);background:var(--card-background-color,#151b22)}.side-top{height:auto;padding:6px;border:0}.side-top h2{display:none}.side-top .button{width:44px;height:44px}.channel-list{display:flex;gap:4px;padding:6px 8px;overflow-x:auto;overscroll-behavior-x:contain;border:0;scrollbar-width:none}.channel-list::-webkit-scrollbar{display:none}.channel-row{flex:0 0 auto}.channel{width:auto;white-space:nowrap;padding:10px 12px}.content{min-height:0;overflow:hidden}.top{height:auto;min-height:56px;padding:8px 10px}.topline{flex-direction:row;align-items:center;gap:6px}.chat-heading{min-width:0}.chat-heading h3{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.header-actions{flex-wrap:nowrap;margin-left:auto}.header-actions .button{padding:8px}.security{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.messages{padding:10px;overscroll-behavior:contain}.message{max-width:94%;padding:8px 10px;margin:5px 0}.compose{position:relative;z-index:2;padding:8px 8px calc(8px + env(safe-area-inset-bottom));min-height:60px;background:var(--primary-background-color,#11151b)}.compose input,.compose .button{min-height:44px;font-size:16px}.modal{padding:0;overflow:hidden;place-items:end stretch}.dialog{width:100%;max-height:calc(100dvh - 16px);margin:0;padding:16px;border-radius:16px 16px 0 0;overflow:auto}.private-menu-popover{position:fixed;top:auto;right:8px;bottom:calc(68px + env(safe-area-inset-bottom));left:8px;max-width:none}}"; this.shadowRoot.append(style); }
    if (!this.shadowRoot.querySelector("#viewport-chat-style")) { const style=document.createElement("style"); style.id="viewport-chat-style"; style.textContent="@media(max-width:700px){:host{box-sizing:border-box;height:var(--ha-chat-vh,100dvh);padding-top:env(safe-area-inset-top)}main{height:100%}.dialog{max-height:calc(var(--ha-chat-vh,100dvh) - env(safe-area-inset-top) - 16px)}}"; this.shadowRoot.append(style); }
    this.shadowRoot.querySelectorAll("[data-channel]").forEach((button) => button.addEventListener("click", () => this.selectChannel(button.dataset.channel)));
    this.shadowRoot.querySelector(".compose")?.addEventListener("submit", (event) => this.sendMessage(event));
    this.shadowRoot.querySelector("#message-input")?.addEventListener("input", (event) => this.queueDraftSave(this._active, event.target.value));
    this.shadowRoot.querySelector("#message-input")?.addEventListener("focus", (event) => { this.updateViewportHeight(); requestAnimationFrame(() => event.target.scrollIntoView({block:"nearest",inline:"nearest"})); });
    this.restoreDraft(this._active);
    this.shadowRoot.querySelector("#reset-key")?.addEventListener("click", () => this.resetEncryption(current));
    this.shadowRoot.querySelector("#new-private")?.addEventListener("click", () => this.privateDialog()); this.shadowRoot.querySelector("#admin")?.addEventListener("click", () => this.adminDialog()); this.shadowRoot.querySelector("#user-settings")?.addEventListener("click", () => this.userSettingsDialog());
    const privateChannelFor=(element) => channels.find((channel) => channel.id === element.dataset.channelId);
    this.shadowRoot.querySelectorAll(".private-info").forEach((button) => button.addEventListener("click", () => this.privateInfoDialog(privateChannelFor(button))));
    this.shadowRoot.querySelectorAll(".silence-private").forEach((button) => button.addEventListener("click", () => this.togglePrivateSilence(privateChannelFor(button))));
    this.shadowRoot.querySelectorAll(".block-private").forEach((button) => button.addEventListener("click", () => this.blockPrivate(privateChannelFor(button))));
    this.shadowRoot.querySelectorAll(".delete-private").forEach((button) => button.addEventListener("click", () => this.deletePrivate(privateChannelFor(button))));
    this.shadowRoot.querySelectorAll("[data-message]:not(.deleted)").forEach(async (element) => { const message = messages.find((item) => item.id === element.dataset.message); if (this._plaintext?.has(message.id)) return; const value=await decryptMessage(message); if (value !== null) { this._plaintext ||= new Map(); this._plaintext.set(message.id,value); element.querySelector(".body").textContent=value; } });
    this.shadowRoot.querySelectorAll(".delete-message").forEach((button) => button.addEventListener("click", () => this.confirmDialog(text.confirmMessageDelete, text.delete, async () => { await this.ws({type:"home_assistant_chat/message/delete", message_id:button.dataset.id}); await this.refreshState(); })));
    const nextMessages=this.shadowRoot.querySelector(".messages"); if (nextMessages && priorScroll) requestAnimationFrame(() => { nextMessages.scrollTop=priorScroll.atBottom ? nextMessages.scrollHeight : priorScroll.top; }); const nextInput=this.shadowRoot.querySelector("#message-input"); if (nextInput && priorInput && !nextInput.disabled) { nextInput.focus({preventScroll:true}); nextInput.setSelectionRange(priorInput.start,priorInput.end); }
  }
}

customElements.define("ha-home-assistant-chat-panel", HomeAssistantChatPanel);
