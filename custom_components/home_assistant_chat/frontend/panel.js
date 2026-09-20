/* Home Assistant Chat: browser-only experimental encryption, no native dialogs. */
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const b64 = (value) => btoa(String.fromCharCode(...new Uint8Array(value)));
const raw = (value) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
const initials = (value) => String(value || "?").trim().split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase();

const STRINGS = {
  en: {
    chat:"Chat", private:"Private chat", device:"Browser device", handle:"Exact enabled Home Assistant username", send:"Send", write:"Write a message",
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
    contactInfo:"Contact info", silence:"Silence", unsilence:"Unmute", userIdentifier:"Home Assistant user ID", moreOptions:"More options", announcements:"Announcements"
  },
  de: {
    chat:"Chat", private:"Privater Chat", device:"Browser-Gerät", handle:"Exakter aktivierter Home-Assistant-Benutzername", send:"Senden",
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
    contactInfo:"Kontaktinformationen", silence:"Stummschalten", unsilence:"Stummschaltung aufheben", userIdentifier:"Home-Assistant-Benutzer-ID", moreOptions:"Weitere Optionen", announcements:"Ankündigungen"
  }
};

function migratedStorageEntry(key, value) {
  if (key === "identity") return ["device", {...value, id:value.id || value.deviceId}];
  if (typeof key === "string" && key.startsWith("channel:")) return [`key:${key.slice("channel:".length)}`, value];
  return [key, value];
}

function migrateStorage(transaction, sourceName, target) {
  const cursorRequest = transaction.objectStore(sourceName).openCursor();
  cursorRequest.onsuccess = () => {
    const cursor = cursorRequest.result; if (!cursor) return;
    const [key, value] = migratedStorageEntry(cursor.key, cursor.value);
    if (sourceName !== "values" || key !== cursor.key) target.put(value, key);
    cursor.continue();
  };
}

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("ha-chat-device-v1", 2);
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
  return {ciphertext:b64(ciphertext), envelope:{version:"ha-chat/1", device_id:identity.id, counter:identity.counter, nonce:b64(nonce), key_id:`${channelId}:${epoch}`, aad:b64(additionalData)}};
}

async function decryptMessage(message) {
  const epoch = message.envelope.key_id.split(":").pop();
  const key = await channelKey(message.channel_id, epoch);
  if (!key) return null;
  try {
    return decoder.decode(await crypto.subtle.decrypt({name:"AES-GCM", iv:raw(message.envelope.nonce), additionalData:raw(message.envelope.aad)}, key, raw(message.ciphertext)));
  } catch { return null; }
}

async function keySecurityCode(key) {
  if (!key) return null;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", await crypto.subtle.exportKey("raw", key)));
  return [...digest.slice(0, 12)].map((value) => value.toString(16).padStart(2, "0")).join("").match(/.{1,4}/g).join(" ");
}

class HomeAssistantChatPanel extends HTMLElement {
  set hass(value) { this._hass = value; if (!this._ready) this.initialize(); }
  set panel(value) { this._panel = value; }
  set narrow(value) { this._narrow = value; }
  get language() { const language=String(globalThis.navigator?.languages?.[0] || globalThis.navigator?.language || this._hass?.language || this._hass?.locale?.language || "en").split(/[-_]/)[0].toLowerCase(); return STRINGS[language] ? language : "en"; }
  get text() { return STRINGS[this.language]; }
  ws(message) { return this._hass.callWS(message); }

  async initialize() {
    this._ready = true; this._channels = []; this._messages = []; this._active = "public"; this.render();
    try {
      const identity = await deviceIdentity();
      await this.ws({type:"home_assistant_chat/device/register", device_id:identity.id, public_key:JSON.stringify(identity.publicKey), label:this.text.device});
      await this.refreshState(); await this.claimOffers(); await this.selectChannel(this._active);
      this._unsubscribe = await this._hass.connection.subscribeMessage((event) => this.handleEvent(event), {type:"home_assistant_chat/subscribe"});
    } catch { this._error = this.text.unavailable; this.render(); }
  }

  disconnectedCallback() { if (typeof this._unsubscribe === "function") this._unsubscribe(); this._unsubscribe = null; }

  async refreshState() {
    this._state = await this.ws({type:"home_assistant_chat/state"});
    this._channels = this._state.channels || []; this._messages = this._state.messages || [];
    if (!this._channels.some((channel) => channel.id === this._active)) this._active = this._channels[0]?.id || null;
    this.render();
  }

  async handleEvent(event) {
    if (event.event === "key_request" && event.request?.channel_id) {
      const channel = this._channels.find((item) => item.id === event.request.channel_id);
      if (channel) await this.shareKey(channel.id, channel.key_epoch || 1);
    }
    if (event.event === "key_offer") await this.claimOffers();
    await this.refreshState();
    if (this._active) await this.updateKeyState(this._active);
  }

  async claimOffers() {
    const identity = await deviceIdentity();
    for (const channel of this._channels) {
      try {
        const state = await this.ws({type:"home_assistant_chat/key/state", channel_id:channel.id});
        for (const group of Object.values(state.offers || {})) for (const offer of Object.values(group)) if (offer.device_id === identity.id) await unwrapChannelKey(channel.id, offer);
      } catch { /* inaccessible channels are omitted */ }
    }
  }

  async updateKeyState(channelId) {
    const channel = this._channels.find((item) => item.id === channelId); if (!channel) return;
    try {
      await this.claimOffers(); this._keyState = await this.ws({type:"home_assistant_chat/key/state", channel_id:channelId});
      const key = await channelKey(channelId, channel.key_epoch || 1); this._securityCode = await keySecurityCode(key); const hasMessages = this._messages.some((message) => message.channel_id === channelId);
      this._waiting = !key && hasMessages;
      if (this._waiting) { const identity = await deviceIdentity(); await this.ws({type:"home_assistant_chat/key/request", channel_id:channelId, device_id:identity.id}); }
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
      const identity = await deviceIdentity();
      for (const target of await this.ws({type:"home_assistant_chat/key/devices", channel_id:channelId})) {
        if (target.id === identity.id) continue;
        await this.ws({type:"home_assistant_chat/key/offer", channel_id:channelId, device_id:target.id, key_id:`${channelId}:${epoch}`, wrapped_key:await wrapChannelKey(key, target)});
      }
    } catch { /* revoked or blocked recipients are skipped */ }
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

  async sendMessage(event) {
    event.preventDefault(); const input = this.shadowRoot.querySelector("#message-input"); const channel = this._channels.find((item) => item.id === this._active);
    const value = input.value.trim(); if (!channel || !value || this.cannotPost(channel)) return; const epoch = channel.key_epoch || 1;
    try {
      if (!await channelKey(channel.id, epoch) && this._messages.some((message) => message.channel_id === channel.id)) { this._waiting = true; await this.updateKeyState(channel.id); return; }
      const encrypted = await encryptMessage(channel.id, epoch, value); await this.shareKey(channel.id, epoch);
      await this.ws({type:"home_assistant_chat/send", channel_id:channel.id, ...encrypted}); input.value = "";
    } catch { this._error = this.text.unavailable; this.render(); }
  }

  privateDialog() {
    const dialog = this.dialog(this.text.private, `<p>${this.text.handle}</p><input id="private-handle" autocomplete="off">`, `<button class="button cancel">${this.text.cancel}</button><button class="button start">${this.text.continue}</button>`);
    dialog.querySelector(".cancel").addEventListener("click", () => dialog.remove());
    dialog.querySelector(".start").addEventListener("click", async () => {
      const handle = dialog.querySelector("#private-handle").value.trim(); dialog.remove();
      try { const result = await this.ws({type:"home_assistant_chat/private", handle, confirm_unblock:false}); await this.refreshState(); await this.selectChannel(result.channel.id); }
      catch (error) {
        if (String(error?.code || error?.message).includes("confirm_unblock")) this.confirmDialog(this.text.confirmUnblock, this.text.continue, async () => { const result = await this.ws({type:"home_assistant_chat/private", handle, confirm_unblock:true}); await this.refreshState(); await this.selectChannel(result.channel.id); });
        else { this._error = this.text.unavailable; this.render(); }
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
    const dialog = this.dialog(this.text.contactInfo, `<div class="row"><span>${this.text.name}</span><strong>${esc(channel.peer.name)}</strong></div><div class="row"><span>${this.text.userIdentifier}</span><code>${esc(channel.peer.id)}</code></div>`, `<button class="button close">${this.text.close}</button>`);
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
    const body = `<p>${this.text.userSettingsHint}</p>${this.blockedUsersMarkup(blocked)}`;
    const dialog = this.dialog(this.text.settings, body, `<button class="button close">${this.text.close}</button>`);
    dialog.querySelector(".close").addEventListener("click", () => dialog.remove());
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
        content.innerHTML = `<label class="row">${this.text.enabled}<input id="setting-enabled" type="checkbox" ${settings.enabled ? "checked" : ""}></label><label class="row">${this.text.allowUsers}<input id="setting-users" type="checkbox" ${settings.allow_users ? "checked" : ""}></label>
          <label class="row">${this.text.retention}<input id="setting-retention" type="number" min="0" max="3650" value="${Number(settings.retention_days || 0)}"></label><label class="row">${this.text.showSecurity}<input id="setting-security" type="checkbox" ${settings.show_security_details ? "checked" : ""}></label><label class="row">${this.text.showDeletedMessages}<input id="setting-deleted-markers" type="checkbox" ${settings.show_deleted_messages ? "checked" : ""}></label><button class="button save-settings">${this.text.save}</button>${this.blockedUsersMarkup(blocked)}`;
        content.querySelector(".save-settings").addEventListener("click", async () => { await this.ws({type:"home_assistant_chat/settings", enabled:content.querySelector("#setting-enabled").checked, allow_users:content.querySelector("#setting-users").checked, retention_days:Number(content.querySelector("#setting-retention").value), show_security_details:content.querySelector("#setting-security").checked, show_deleted_messages:content.querySelector("#setting-deleted-markers").checked}); await reload(); await show("settings"); });
        this.bindUnblockActions(content, async () => { await reload(); await show("settings"); });
      }
    };
    dialog.querySelector(".close").addEventListener("click", () => dialog.remove());
    dialog.querySelectorAll("[data-tab]").forEach((button) => button.addEventListener("click", () => show(button.dataset.tab))); await show("channels");
  }

  render() {
    if (!this.shadowRoot) this.attachShadow({mode:"open"}); const text = this.text; const channels = this._channels || [];
    const current = channels.find((channel) => channel.id === this._active) || channels[0]; if (current && !this._active) this._active = current.id;
    const messages = (this._messages || []).filter((message) => message.channel_id === this._active); const readOnly = this.cannotPost(current); const peer = current?.peer;
    const security = this._state?.settings?.show_security_details && this._keyState ? `<p class="security">🔒 ${text.ready} · ${text.experimental} · ${this._keyState.device_count} ${text.deviceCount} · ${text.security}: ${esc(this._securityCode || "—")}</p>` : "";
    this.shadowRoot.innerHTML = `<style>:host{display:block;height:100dvh;min-height:0;overflow:hidden;background:var(--primary-background-color,#11151b);color:var(--primary-text-color,#e7e9ed);font:14px system-ui}*{box-sizing:border-box}main{--chat-header-height:104px;height:100%;min-height:0;display:grid;grid-template-columns:250px minmax(0,1fr);max-width:1200px;margin:auto}.side{min-height:0;border-right:1px solid var(--divider-color,#2d3540);overflow:auto}.side-top{height:var(--chat-header-height);padding:14px 12px;display:flex;align-items:center;justify-content:space-between;gap:8px;border-bottom:1px solid var(--divider-color,#2d3540)}.side-top h2{margin:0}.side-top .button{display:grid;place-items:center;width:34px;height:34px;padding:0;font-size:20px;line-height:1}.channel-list{padding:14px 12px}.channel-row{display:flex;align-items:center}.channel-row .channel{flex:1;min-width:0}.channel{display:block;width:100%;text-align:left;background:none;border:0;color:inherit;padding:10px;border-radius:8px;cursor:pointer}.active{background:var(--secondary-background-color,#2d3748)}.content{display:flex;flex-direction:column;min-width:0;min-height:0}.top{height:var(--chat-header-height);padding:14px 18px;border-bottom:1px solid var(--divider-color,#2d3540)}.topline,.header-actions,.chat-heading,.message-head,.row,.actions{display:flex;align-items:center;gap:8px}.topline,.message-head,.row{justify-content:space-between}.header-actions{justify-content:flex-end;flex-wrap:wrap}.top h3{margin:.25rem 0}.private-menu{position:relative}.private-menu summary{display:grid;place-items:center;width:34px;height:34px;border-radius:8px;cursor:pointer;list-style:none}.private-menu summary::-webkit-details-marker{display:none}.private-menu summary:hover{background:var(--secondary-background-color,#2d3748)}.private-menu-popover{position:absolute;top:38px;left:0;z-index:10;display:grid;min-width:190px;padding:6px;border:1px solid var(--divider-color,#465365);border-radius:10px;background:var(--card-background-color,#202a36);box-shadow:0 8px 24px #0007}.sidebar-private-menu .private-menu-popover{left:auto;right:0}.private-menu-popover .button{border:0;text-align:left;background:transparent}.peer-avatar{display:inline-grid;place-items:center;width:34px;height:34px;border-radius:50%;background:var(--accent-color,#03a9f4);color:#fff;font-weight:700}.security{margin:.35rem 0 0;color:var(--success-color,#58c28b);font-size:.85rem}.messages{flex:1;min-height:0;overflow:auto;padding:18px}.message{padding:10px;margin:7px 0;background:var(--card-background-color,#202a36);border-radius:10px;max-width:78%;overflow-wrap:anywhere}.message.deleted{opacity:.7;font-style:italic}.message-head{align-items:flex-start;margin-bottom:4px}.message-head small{min-width:0;padding-top:4px}.delete-message{display:grid;place-items:center;flex:0 0 28px;width:28px;height:28px;padding:0;border:0;background:transparent}.delete-message ha-icon{--mdc-icon-size:18px}.mine{margin-left:auto;background:#194e5c}.compose{display:flex;flex:0 0 auto;gap:8px;padding:12px;border-top:1px solid var(--divider-color,#2d3540)}.compose input{flex:1;min-width:0}.button,input,select{border:1px solid var(--divider-color,#465365);border-radius:8px;background:var(--card-background-color,#1b232d);color:inherit;padding:9px}.button{cursor:pointer}.button:disabled,input:disabled{opacity:.55;cursor:not-allowed}.danger{color:var(--error-color,#ffb4ab)}.modal{position:fixed;inset:0;z-index:20;background:#0009;display:grid;place-items:center;padding:20px}.dialog{width:min(700px,100%);max-height:90vh;overflow:auto;background:var(--card-background-color,#202a36);border:1px solid var(--divider-color,#4a5868);border-radius:14px;padding:20px}.actions{justify-content:flex-end;margin-top:16px}.tabs{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:14px}.tabs button{background:var(--secondary-background-color,#2d3748);color:inherit;border:0;border-radius:7px;padding:8px;cursor:pointer}.row{padding:8px;border-bottom:1px solid var(--divider-color,#35404d)}label{display:grid;gap:5px;margin:.6rem 0}select[multiple]{min-height:9rem}@media(max-width:700px){main{--chat-header-height:auto;grid-template-columns:1fr;grid-template-rows:auto minmax(0,1fr)}.side{border-right:0}.side-top{height:auto}.channel-list{display:flex;gap:4px;overflow:auto;border-bottom:1px solid var(--divider-color,#2d3540)}.channel-row{flex:0 0 auto}.channel{white-space:nowrap;width:auto}.top{height:auto}.message{max-width:92%}.topline{align-items:flex-start;flex-direction:column}.header-actions{justify-content:flex-start}}</style><main>
      <aside class="side"><div class="side-top"><h2>${text.chat}</h2><button class="button" id="new-private" aria-label="${esc(text.private)}" title="${esc(text.private)}">+</button></div><div class="channel-list">${channels.map((channel) => `<div class="channel-row"><button class="channel ${channel.id === this._active ? "active" : ""}" data-channel="${esc(channel.id)}">${esc(this.channelName(channel))}</button>${this.privateMenu(channel,"sidebar")}</div>`).join("")}</div></aside>
      <section class="content"><header class="top"><div class="topline"><div class="chat-heading">${current?.kind === "private" && peer ? `<span class="peer-avatar">${esc(initials(peer.name))}</span><h3>${esc(peer.name)}</h3>${this.privateMenu(current)}` : `<h3>${esc(this.channelName(current))}</h3>`}</div><div class="header-actions">${this._state?.is_admin ? `<button class="button" id="admin">${text.admin}</button>` : `<button class="button" id="user-settings">${text.settings}</button>`}</div></div>${security}</header>
      <div class="messages">${this._waiting ? `<p>${text.waiting}</p>` : ""}${this._error ? `<p>${esc(this._error)}</p>` : ""}${messages.length ? messages.map((message) => `<article class="message ${message.sender_id === this._state?.user_id ? "mine" : ""} ${message.deleted ? "deleted" : ""}" data-message="${esc(message.id)}"><div class="message-head"><small>${esc(message.sender_name || "User")} · ${new Date(message.created * 1000).toLocaleString(this.language === "de" ? "de-DE" : "en-US")}</small>${!message.deleted && message.sender_id === this._state?.user_id ? `<button class="button danger delete-message" data-id="${esc(message.id)}" aria-label="${esc(text.delete)}" title="${esc(text.delete)}"><ha-icon icon="mdi:delete-outline" aria-hidden="true"></ha-icon></button>` : ""}</div><span class="body">${message.deleted ? text.messageDeleted : text.encrypted}</span></article>`).join("") : `<p>${text.noMessages}</p>`}</div>
      <form class="compose"><input id="message-input" maxlength="4000" autocomplete="off" placeholder="${esc(readOnly ? text.cannotPost : text.write)}" ${readOnly ? "disabled" : ""}><button class="button" ${readOnly ? "disabled" : ""}>${text.send}</button></form></section></main>`;
    this.shadowRoot.querySelectorAll("[data-channel]").forEach((button) => button.addEventListener("click", () => this.selectChannel(button.dataset.channel)));
    this.shadowRoot.querySelector(".compose")?.addEventListener("submit", (event) => this.sendMessage(event));
    this.shadowRoot.querySelector("#new-private")?.addEventListener("click", () => this.privateDialog()); this.shadowRoot.querySelector("#admin")?.addEventListener("click", () => this.adminDialog()); this.shadowRoot.querySelector("#user-settings")?.addEventListener("click", () => this.userSettingsDialog());
    const privateChannelFor=(element) => channels.find((channel) => channel.id === element.dataset.channelId);
    this.shadowRoot.querySelectorAll(".private-info").forEach((button) => button.addEventListener("click", () => this.privateInfoDialog(privateChannelFor(button))));
    this.shadowRoot.querySelectorAll(".silence-private").forEach((button) => button.addEventListener("click", () => this.togglePrivateSilence(privateChannelFor(button))));
    this.shadowRoot.querySelectorAll(".block-private").forEach((button) => button.addEventListener("click", () => this.blockPrivate(privateChannelFor(button))));
    this.shadowRoot.querySelectorAll(".delete-private").forEach((button) => button.addEventListener("click", () => this.deletePrivate(privateChannelFor(button))));
    this.shadowRoot.querySelectorAll("[data-message]:not(.deleted)").forEach(async (element) => { const message = messages.find((item) => item.id === element.dataset.message); element.querySelector(".body").textContent = await decryptMessage(message) || text.encrypted; });
    this.shadowRoot.querySelectorAll(".delete-message").forEach((button) => button.addEventListener("click", () => this.confirmDialog(text.confirmMessageDelete, text.delete, async () => { await this.ws({type:"home_assistant_chat/message/delete", message_id:button.dataset.id}); await this.refreshState(); })));
  }
}

customElements.define("ha-home-assistant-chat-panel", HomeAssistantChatPanel);
