# Architecture and future federation boundary

The integration separates chat/domain state (`store.py`) from the Home Assistant WebSocket adapter (`websocket.py`). Messages use `protocol_version`, globally unique local IDs, `origin_server_id`, channel routing metadata, and a portable encrypted envelope. A future bridge must translate this protocol at the transport boundary rather than importing Home Assistant internals.

Each local Home Assistant user also receives a stable, server-scoped numeric identity. It is generated once with collision checking and persisted separately from the Home Assistant user ID and display name. Private-chat lookup accepts that number (or the legacy exact display name during migration); `NUMBER@HOST` and `NUMBER@HOST:PORT` are reserved federation syntax and currently return an explicit not-supported error without making a network request.

Recovery bundles are opaque, client-encrypted records. The server stores ciphertext, salt, nonce, and KDF metadata only; the recovery secret is never stored server-side. A new device still requires a one-time QR/code transfer or approval from an existing device. Recovery storage is scoped to the authenticated HA user and is not a federation credential.

The v1 server persists ciphertext only for message content. Device private keys remain in browser IndexedDB; channel keys are wrapped between enrolled devices with ECDH-derived AES-GCM keys. Automatic sharing and recovery are implemented but remain experimental and have not received an independent cryptographic audit. Replay protection requires a future bridge to enforce message IDs, sender device counters, expiry, and authenticated origin. Trust verification must bind device keys to an out-of-band security code or equivalent user verification. Discovery must be explicit and opt-in (no ambient LAN enumeration), with origin allowlists, rate limits, and administrator approval.

Threat model: this reduces plaintext exposure to the server database, but not to the active Home Assistant process, browser runtime, XSS, backups, logs, compromised admins, or enrolled devices. It offers no forward secrecy, post-compromise security, metadata privacy, or standards-compliant MLS guarantees.

## Key epochs across future transports

Channel ciphertext and wrapped keys are retained per key epoch. Losing one epoch
must never delete messages or prevent a later epoch from carrying new messages.
A last-resort reset is a compare-and-swap operation: the client supplies the
epoch it observed and the channel authority advances it only if that value is
still current. This prevents simultaneous group participants from repeatedly
invalidating one another's replacement keys.

For federation, every channel must have one authoritative home server for epoch
ordering. A `key_reset` event must be authenticated, assigned an ordered event
identifier, and replicated to participating servers before they accept messages
for the new epoch. Remote servers must not independently invent an epoch.

MeshCore fallback may eventually queue encrypted messages and transport already
authorized protocol events, but it must not perform an offline key reset. When
the authoritative server is unreachable, a reset request stays pending until
connectivity returns. This avoids splitting a private or group chat into
incompatible encryption histories. These constraints apply regardless of the
eventual federation transport or identity format.
