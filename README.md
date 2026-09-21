# Home Assistant Chat

> [!WARNING]
> **Experimental testing version.** This project is an early prototype. Features,
> stored data and encryption behavior may change or break. Do not rely on it for
> emergencies, sensitive communication or your only copy of important messages.

## Add to HACS

[![Open your Home Assistant instance and add this repository to HACS](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=pmssoftware&repository=home-assistant-chat&category=integration)

Home Assistant Chat is a local custom integration with a native sidebar panel.
It runs inside Home Assistant and does not require a separate add-on or chat
server for local use.

Current experimental version: **0.3.5**

## Installation

1. Select the **Add to HACS** button above.
2. Confirm this repository in HACS and install **Home Assistant Chat**.
3. Restart Home Assistant.
4. Open **Settings → Devices & services → Add integration**.
5. Select **Home Assistant Chat**.

If the button does not open HACS, add this custom repository manually:

```text
https://github.com/pmssoftware/home-assistant-chat
```

Choose **Integration** as its category.

## Current prototype

- Native Home Assistant Chat sidebar
- Public chat and announcements
- Private chats and restricted groups
- User blocking and personal chat muting
- Message and entire private-chat deletion
- English and German interface
- Experimental browser-side message encryption
- Stable eight-digit local contact identities
- Local QR display and camera/image scanning for contact identities
- Client-encrypted recovery codes for restoring channel keys on a new device
- Administrator controls for access, channels, moderation and devices

Encryption remains experimental. Browser Web Crypto and IndexedDB hold device
private keys while Home Assistant stores ciphertext and routing metadata. This
prototype does not yet provide verified identity, forward secrecy,
post-compromise security or standards-compliant MLS.

## Roadmap

1. Stabilize local messaging, encryption recovery and device handling.
2. Add verified device linking and signed device certificates.
3. Add federation using addresses such as `number@server-address` over a
   dedicated chat port.
4. Add reliable delivery, federation security and server administration.
5. After federation works, investigate optional MeshCore fallback messaging
   when the normal internet or VPN connection is unavailable.
6. Expand translations and accessibility with community contributions.

MeshCore would require compatible hardware at participating endpoints and must
never silently weaken identity, authorization or encryption guarantees.

## Compatibility

The bundled icon and logo require Home Assistant 2026.3 or newer. The
integration is intended for Home Assistant OS, Container and Core installations
that support custom integrations.

For implementation and security details, see
[the architecture notes](docs/architecture.md).

## Development

Run the test suite with:

```text
pytest -q
```

Contributions and testing feedback are welcome while the project is marked
experimental.

Compatibility is not guaranteed during experimental releases. After the first
stable release, identities and addresses will remain permanent, persisted data
will use tested additive migrations, and protocol changes will be versioned with
explicit deprecation periods.
