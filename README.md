# Home Assistant Chat

A local-only Home Assistant custom integration with a native Chat sidebar panel. It has no add-on or separate server process and is intended for Home Assistant OS, Container, and Core installations that support custom integrations.

[![Open your Home Assistant instance and add this repository to HACS](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=pmssoftware&repository=home-assistant-chat&category=integration)

## Status

This is an experimental v1 implementation. It includes config flow, persistent local storage and migrations, push WebSocket transport, authorization-filtered channels, exact-handle private-chat entry, public/restricted/announcement channel rules, moderation and blocking commands, user-seen tracking, browser device enrollment, AES-GCM message encryption, ECDH-wrapped channel-key offers, replay-resistant envelopes, and a browser device key vault.

Current integration version: **0.1.7**

## Installation with HACS

1. Select the **Add repository to HACS** button above.
2. Confirm the repository in HACS and install **Home Assistant Chat**.
3. Restart Home Assistant.
4. Open **Settings → Devices & services → Add integration**, then select **Home Assistant Chat**.

For manual installation, copy `custom_components/home_assistant_chat` into the Home Assistant configuration directory, restart Home Assistant, and add the integration through **Settings → Devices & services**.

Encryption is experimental: browser Web Crypto/IndexedDB holds device private keys, while the server stores ciphertext and routing metadata. This is not MLS, does not provide verified identity, and currently does not protect a compromised browser, Home Assistant host, or malicious enrolled device. See [docs/architecture.md](docs/architecture.md).

## Roadmap

- Add an optional [MeshCore](https://meshcore.io/) fallback transport for basic
  text messaging when the normal internet or VPN connection to Home Assistant
  is unavailable.
- Bridge through compatible MeshCore companion hardware using the documented
  companion protocol, with queued delivery and automatic return to the normal
  Home Assistant WebSocket transport when connectivity recovers.
- Keep fallback status visible and require explicit setup; MeshCore hardware is
  required at the participating endpoints, and the fallback must not silently
  weaken chat identity, authorization, or encryption guarantees.

## Development

```text
pytest -q
```

The administrator panel includes channel and membership management, per-user access, moderation, encrypted-device revocation, retention settings, and optional encryption details. Private chats support exact-name creation, blocking, deleting for both participants, and automatic unblocking when the blocker deliberately starts the chat again.

There is no verified identity binding, forward secrecy, post-compromise security, or standards-compliant MLS. Home Assistant runtime testing and browser crypto round-trip automation still need to be completed on a system with Home Assistant and Node.js installed. No network service or federation is included.

## Feature matrix

| Capability | v1 status |
| --- | --- |
| Native sidebar panel and config flow | Implemented |
| Public, restricted, private, and announcement channels | Implemented, including membership editing |
| Exact-handle privacy and two-sided blocking | Implemented |
| Per-user access, seen state, mute, deletion, retention | Implemented in the API and administrator UI |
| Browser-only device keys and encrypted envelopes | Experimental implementation |
| Key requests, wrapped offers, epoch rotation, waiting state | Implemented experimentally |
| Security code and device administration | Implemented; identity verification is not provided |
| Federation / MLS / verified identity | Not implemented |
