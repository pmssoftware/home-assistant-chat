# Home Assistant Chat

A local-only Home Assistant custom integration with a native Chat sidebar panel. It has no add-on or separate server process and is intended for Home Assistant OS, Container, and Core installations that support custom integrations.

## Status

This is an experimental v1 implementation. It includes config flow, persistent local storage and migrations, push WebSocket transport, authorization-filtered channels, exact-handle private-chat entry, public/restricted/announcement channel rules, moderation and blocking commands, user-seen tracking, browser device enrollment, AES-GCM message encryption, ECDH-wrapped channel-key offers, replay-resistant envelopes, and a browser device key vault.

Install by copying `custom_components/home_assistant_chat` into the Home Assistant configuration directory and adding it through Settings → Devices & services.

Encryption is experimental: browser Web Crypto/IndexedDB holds device private keys, while the server stores ciphertext and routing metadata. This is not MLS, does not provide verified identity, and currently does not protect a compromised browser, Home Assistant host, or malicious enrolled device. See [docs/architecture.md](docs/architecture.md).

## Development

```text
pytest -q
```

The current UI is intentionally compact: channel membership editing, user allow-list editing, device/security-code views, and mute controls are exposed through the domain/WebSocket API but are not yet surfaced as complete administrator screens. There is no verified identity binding, forward secrecy, post-compromise security, or standards-compliant MLS. No network service, GitHub publication, live installation, or federation is included.

## Feature matrix

| Capability | v1 status |
| --- | --- |
| Native sidebar panel and config flow | Implemented |
| Public, restricted, private, and announcement channels | Domain/API implemented; compact admin UI included |
| Exact-handle privacy and two-sided blocking | Implemented |
| Per-user access, seen state, mute, deletion, retention | Implemented in domain/API |
| Browser-only device keys and encrypted envelopes | Experimental implementation |
| Key requests, wrapped offers, epoch rotation, waiting state | Implemented in domain/API; recovery UX limited |
| Security code and device administration | Admin-gated API/UI data; verification is not provided |
| Federation / MLS / verified identity | Not implemented |
