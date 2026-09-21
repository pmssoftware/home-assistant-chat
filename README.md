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

Current experimental version: **0.4.3**

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
- Client-encrypted photo and video attachments up to 25 MB, with an administrator enable/disable switch
- English and German interface
- Experimental browser-side message encryption (mandatory in this prototype)
- Stable eight-digit local contact identities
- Local QR display and camera/image scanning for contact identities
- Client-encrypted recovery codes for restoring channel keys on a new device
- Administrator controls for access, channels, moderation and devices

Encryption remains experimental. It is not equivalent to WhatsApp or a
security-audited end-to-end encrypted messenger.

## Roadmap

1. Stabilize local messaging, encryption recovery and device handling.
2. Add verified device linking and signed device certificates.
3. Add federation using addresses such as `number@server-address`. Separate
   backend ports for local clients and federation are planned, but are not
   implemented yet.
4. Add reliable delivery, federation security and server administration.
5. After federation works, investigate optional MeshCore fallback messaging
   when the normal internet or VPN connection is unavailable.
6. Expand translations and accessibility with community contributions.

MeshCore would require compatible hardware at participating endpoints and must
never silently weaken identity, authorization or encryption guarantees.

## Security and threat model

Message content is encrypted in the browser before it is sent. Home Assistant
stores ciphertext, recovery ciphertext, and the routing data needed to deliver
keys and messages. The Home Assistant server is trusted for account
membership, identities, metadata, and key routing; this prototype is not
resistant to a malicious or compromised server, a malicious custom frontend,
same-origin code, a browser extension, or a compromised device.

Participants, timing, device IDs, channel IDs, and other metadata remain
visible to the server. For attachments, the server also sees the encrypted file
size and its channel/sender association, but not the encrypted filename, media
type, or contents. Browser keys are extractable so that recovery and device
sharing can work, and local drafts are stored as plaintext in browser
IndexedDB. A recovery code protects an encrypted recovery bundle; browser key
storage and recovery data are scoped to the Home Assistant server and user.
Deleted ciphertext cannot be guaranteed to disappear from backups.

This software is experimental and unaudited. Do not rely on it for high-risk
secrets or safety-critical communication.

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
