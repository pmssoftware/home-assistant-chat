"""Transport-independent chat rules and serializable state."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .const import MAX_MESSAGE_LENGTH, PROTOCOL_VERSION

HANDLE_RE = re.compile(r"^.{1,128}$", re.DOTALL)
IDENTITY_RE = re.compile(r"^([1-9]\d{7})(?:@([^:]+)(?::(\d+))?)?$")
FEDERATION_HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$", re.IGNORECASE)
MAX_RECOVERY_FIELD = 16384
MAX_DEVICES_PER_USER = 32
MAX_WRAPPED_OFFER = 16384
MAX_PENDING_KEY_REQUESTS_PER_DEVICE_CHANNEL = 1
MAX_PENDING_KEY_REQUESTS_PER_USER = 64
MAX_PENDING_KEY_REQUESTS = 1024
MAX_CIPHERTEXT_BYTES = MAX_MESSAGE_LENGTH * 4 + 16
MAX_COUNTER = 2**53 - 1

def _decode_standard_b64(value: Any, *, field: str, max_decoded: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or len(value) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value):
        raise ValueError(f"invalid_{field}")
    if max_decoded is not None and len(value) > ((max_decoded + 2) // 3) * 4:
        raise ValueError(f"invalid_{field}")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError, base64.binascii.Error) as err:
        raise ValueError(f"invalid_{field}") from err
    if base64.b64encode(decoded).decode() != value:
        raise ValueError(f"invalid_{field}")
    return decoded

def _public_jwk(public_key: Any) -> dict[str, Any]:
    try: key = json.loads(public_key)
    except (TypeError, ValueError) as err: raise ValueError("invalid_device") from err
    if not isinstance(key, dict) or set(key) != {"kty","crv","x","y","ext","key_ops"} or key.get("kty") != "EC" or key.get("crv") != "P-256" or key.get("ext") is not True or key.get("key_ops") != []:
        raise ValueError("invalid_device")
    for field in ("x", "y"):
        value = key.get(field)
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value): raise ValueError("invalid_device")
        try: raw = base64.urlsafe_b64decode(value + "==")
        except (ValueError, TypeError, base64.binascii.Error) as err: raise ValueError("invalid_device") from err
        if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value: raise ValueError("invalid_device")
    return key

def normalize_federation_endpoint(address: Any, port: Any) -> tuple[str, int]:
    """Validate the host/port advertised in an identity QR code.

    This is deliberately an endpoint validator only; it performs no DNS lookup
    and does not authorize or initiate federation connections.
    """
    if not isinstance(address, str):
        raise ValueError("invalid_federation_address")
    host = address.strip()
    if not host or len(host) > 253 or any(ch.isspace() for ch in host):
        raise ValueError("invalid_federation_address")
    if ":" in host or host.startswith("[") or host.endswith("]"):
        raise ValueError("invalid_federation_address")
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        if not FEDERATION_HOST_RE.fullmatch(host) or len(host.rstrip(".").split(".")) > 127:
            raise ValueError("invalid_federation_address")
        canonical_host = host.rstrip(".").lower()
    else:
        if parsed.version != 4:
            raise ValueError("invalid_federation_address")
        canonical_host = parsed.compressed
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("invalid_federation_port")
    return canonical_host, port

def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"

def validate_envelope(ciphertext: Any, envelope: Any) -> None:
    if not isinstance(ciphertext, str): raise ValueError("invalid_ciphertext")
    ciphertext_bytes = _decode_standard_b64(ciphertext, field="ciphertext", max_decoded=MAX_CIPHERTEXT_BYTES)
    if not 16 <= len(ciphertext_bytes) <= MAX_CIPHERTEXT_BYTES: raise ValueError("invalid_ciphertext")
    if not isinstance(envelope, dict): raise ValueError("invalid_envelope")
    required = {"version", "device_id", "counter", "nonce", "key_id", "aad"}
    allowed = required | {"key_commitment"}
    if set(envelope) - allowed or not required <= set(envelope) or envelope["version"] != PROTOCOL_VERSION:
        raise ValueError("invalid_envelope")
    device_id = envelope["device_id"]
    try: parsed_device = uuid.UUID(device_id)
    except (ValueError, TypeError, AttributeError) as err: raise ValueError("invalid_device") from err
    if not isinstance(device_id, str) or str(parsed_device) != device_id or parsed_device.version != 4: raise ValueError("invalid_device")
    if not isinstance(envelope["key_id"], str) or not envelope["key_id"] or len(envelope["key_id"]) > 256: raise ValueError("invalid_envelope")
    counter = envelope["counter"]
    if isinstance(counter, bool) or not isinstance(counter, int) or not 1 <= counter <= MAX_COUNTER: raise ValueError("invalid_counter")
    nonce = _decode_standard_b64(envelope["nonce"], field="nonce", max_decoded=12)
    if len(nonce) != 12: raise ValueError("invalid_nonce")
    _decode_standard_b64(envelope["aad"], field="aad", max_decoded=1024)
    if "key_commitment" in envelope:
        commitment = envelope["key_commitment"]
        if not isinstance(commitment, str) or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", commitment): raise ValueError("invalid_key_commitment")

@dataclass(slots=True)
class ChatDomain:
    data: dict[str, Any]

    @classmethod
    def fresh(cls, server_id: str | None = None) -> "ChatDomain":
        sid = server_id or new_id("server")
        return cls({"schema_version": 5, "server_id": sid, "channels": {
            "public": {"id":"public","kind":"public","name":"Public chat","restricted":False,"members":[],"key_epoch":1},
            "announcements": {"id":"announcements","kind":"announcement","name":"Announcements","restricted":False,"members":[],"key_epoch":1},
        }, "messages": {}, "blocks": {}, "mutes": {}, "silenced": {}, "devices": {}, "keys": {}, "key_requests": {}, "key_commitments": {}, "seen": {}, "replay": {}, "users": {"allowed": None}, "identities": {}, "identity_users": {}, "recovery": {}})

    def migrate(self) -> bool:
        changed = False; version = self.data.get("schema_version", 0); defaults = self.fresh(self.data.get("server_id")).data
        for key, value in defaults.items():
            if key not in self.data: self.data[key] = value; changed = True
        announcements = self.data.get("channels", {}).get("announcements")
        if announcements and announcements.get("restricted") is not False:
            announcements["restricted"] = False
            changed = True
        if version < 5: self.data["schema_version"] = 5; changed = True
        if "identities" not in self.data: self.data["identities"] = {}; changed = True
        if "identity_users" not in self.data: self.data["identity_users"] = {}; changed = True
        repaired={}
        for user_id, value in self.data["identities"].items():
            try: number=int(value)
            except (TypeError,ValueError): continue
            if IDENTITY_RE.fullmatch(str(number)) and str(number) not in repaired: repaired[str(number)]=user_id
        if repaired != self.data["identity_users"]: self.data["identity_users"]=repaired; changed=True
        # Key offers used to be stored as channel -> key -> target -> offer.
        # Keep each sender's offer independently so a second sender cannot
        # overwrite the first one.  Invalid persisted records are discarded.
        migrated_keys = {}
        for channel_id, channel_keys in (self.data.get("keys") or {}).items():
            if not isinstance(channel_keys, dict):
                continue
            migrated_channel = {}
            for key_id, targets in channel_keys.items():
                if not isinstance(targets, dict):
                    continue
                migrated_targets = {}
                for target_id, value in targets.items():
                    if isinstance(value, dict) and isinstance(value.get("wrapped_key"), str):
                        candidates = [(value.get("from_device_id"), value)]
                    elif isinstance(value, dict):
                        candidates = value.items()
                    else:
                        continue
                    sender_offers = {}
                    for sender_id, offer in candidates:
                        try: parsed_sender = uuid.UUID(sender_id)
                        except (ValueError, TypeError, AttributeError): continue
                        if str(parsed_sender) != sender_id or parsed_sender.version != 4:
                            continue
                        try: parsed_target = uuid.UUID(target_id)
                        except (ValueError, TypeError, AttributeError): continue
                        if str(parsed_target) != target_id or parsed_target.version != 4 or not isinstance(offer, dict) or offer.get("device_id") != target_id or offer.get("from_device_id") != sender_id or not isinstance(offer.get("wrapped_key"), str) or not offer["wrapped_key"]:
                            continue
                        sender_offers[sender_id] = offer
                    if sender_offers:
                        migrated_targets[target_id] = sender_offers
                if migrated_targets:
                    migrated_channel[key_id] = migrated_targets
            if migrated_channel:
                migrated_keys[channel_id] = migrated_channel
        if migrated_keys != self.data.get("keys", {}):
            self.data["keys"] = migrated_keys
            changed = True
        return changed

    def get_recovery_bundle(self, user_id: str) -> dict[str, Any] | None:
        bundle=self.data.get("recovery", {}).get(user_id)
        return dict(bundle) if bundle else None

    def set_recovery_bundle(self, user_id: str, bundle: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(bundle, dict) or bundle.get("version") != 1: raise ValueError("invalid_recovery_bundle")
        required={"version","ciphertext","salt","nonce","kdf"}
        if set(bundle) != required: raise ValueError("invalid_recovery_bundle")
        kdf=bundle.get("kdf")
        if not isinstance(kdf,dict) or set(kdf)!={"name","hash","iterations"} or kdf.get("name") != "PBKDF2" or kdf.get("hash") != "SHA-256" or isinstance(kdf.get("iterations"),bool) or not isinstance(kdf.get("iterations"),int) or not 200000 <= kdf["iterations"] <= 1000000: raise ValueError("invalid_recovery_bundle")
        for field in ("ciphertext","salt","nonce"):
            if not isinstance(bundle.get(field), str) or not bundle[field] or len(bundle[field]) > MAX_RECOVERY_FIELD: raise ValueError("invalid_recovery_bundle")
            try: decoded=_decode_standard_b64(bundle[field], field="recovery", max_decoded=MAX_RECOVERY_FIELD)
            except (ValueError, TypeError, base64.binascii.Error) as err: raise ValueError("invalid_recovery_bundle") from err
            if field == "nonce" and len(decoded) != 12: raise ValueError("invalid_recovery_bundle")
            if field == "salt" and not 16 <= len(decoded) <= 128: raise ValueError("invalid_recovery_bundle")
            if field == "ciphertext" and not 16 <= len(decoded) <= MAX_RECOVERY_FIELD: raise ValueError("invalid_recovery_bundle")
        stored={"version":1,"ciphertext":bundle["ciphertext"],"salt":bundle["salt"],"nonce":bundle["nonce"],"kdf":dict(kdf),"updated":time.time()}
        self.data.setdefault("recovery", {})[user_id]=stored
        return stored

    def ensure_identity(self, user_id: str) -> int:
        if user_id in self.data["identities"]:
            try: number=int(self.data["identities"][user_id])
            except (TypeError,ValueError): number=0
            if IDENTITY_RE.fullmatch(str(number)) and self.data["identity_users"].get(str(number)) in (None,user_id):
                self.data["identities"][user_id]=number; self.data["identity_users"][str(number)]=user_id; return number
            self.data["identities"].pop(user_id,None)
        used=set()
        for value in self.data["identities"].values():
            try: used.add(int(value))
            except (TypeError,ValueError): pass
        number=secrets.randbelow(90000000)+10000000
        while number in used: number=secrets.randbelow(90000000)+10000000
        self.data["identities"][user_id]=number; self.data["identity_users"][str(number)]=user_id
        return number

    def parse_identity(self, value: str) -> tuple[int, str | None]:
        if not isinstance(value,str) or not HANDLE_RE.match(value): raise ValueError("invalid_identity")
        match=IDENTITY_RE.fullmatch(value.strip())
        if not match: return 0, None
        number=int(match.group(1)); host=match.group(2)
        if host: raise ValueError("federated_identity_not_supported")
        return number, None

    def can_access(self, user_id: str, globally_enabled: bool, allowed_users: set[str] | None, admins: set[str] | None = None) -> bool:
        return globally_enabled and (user_id in (admins or set()) or (allowed_users is None or user_id in allowed_users))

    def channels_for(self, user_id: str, admins: set[str], globally_enabled: bool, allowed_users: set[str] | None, include_members: bool = False) -> list[dict[str, Any]]:
        if not self.can_access(user_id, globally_enabled, allowed_users, admins): return []
        return [dict(ch) if include_members and user_id in admins else {k:v for k,v in ch.items() if k != "members"} for ch in self.data["channels"].values() if (ch.get("kind") == "private" and len(ch.get("members",[])) == 2 and user_id in ch.get("members",[]) and not self.private_blocked(*ch["members"])) or (ch.get("kind") != "private" and (not ch.get("restricted",False) or user_id in ch.get("members",[]) or user_id in admins))]

    def can_post(self, channel_id: str, user_id: str, admins: set[str]) -> bool:
        channel = self.data["channels"].get(channel_id)
        if not channel: raise KeyError("channel_not_found")
        if self.data["mutes"].get(user_id): return False
        if channel["kind"] == "private" and self.private_blocked(*channel["members"]): return False
        if channel["kind"] == "announcement": return user_id in admins
        return not channel["restricted"] or user_id in channel["members"] or user_id in admins

    def can_view(self, channel_id: str, user_id: str, admins: set[str]) -> bool:
        channel=self.data["channels"].get(channel_id)
        if not channel: return False
        if channel["kind"] == "announcement": return not channel["restricted"] or user_id in channel["members"] or user_id in admins
        if channel["kind"] == "private": return user_id in channel["members"] and not self.private_blocked(*channel["members"])
        return not channel["restricted"] or user_id in channel["members"] or user_id in admins

    def add_channel(self, actor: str, admins: set[str], name: str, kind: str, restricted: bool, members: set[str]) -> dict[str, Any]:
        if actor not in admins: raise PermissionError("admin_required")
        if kind not in {"public", "group", "announcement"} or not name.strip(): raise ValueError("invalid_channel")
        channel = {"id":new_id("channel"),"kind":kind,"name":name.strip()[:80],"restricted":restricted,"members":sorted(members),"key_epoch":1}
        self.data["channels"][channel["id"]] = channel; return channel

    def edit_channel(self, actor: str, admins: set[str], channel_id: str, name: str, restricted: bool, members: set[str], kind: str | None = None) -> dict[str, Any]:
        if actor not in admins: raise PermissionError("admin_required")
        channel=self.data["channels"].get(channel_id)
        if not channel or channel_id in {"public","announcements"} and channel["kind"] in {"public","announcement"} and not name.strip(): raise ValueError("invalid_channel")
        if not channel: raise KeyError("channel_not_found")
        if channel_id == "public":
            kind, restricted, members = "public", False, set()
        elif channel_id == "announcements":
            kind, restricted, members = "announcement", False, set()
        elif kind is not None:
            if kind not in {"public", "group", "announcement"}: raise ValueError("invalid_channel")
            channel["kind"] = kind
        channel.update(name=name.strip()[:80],restricted=restricted,members=sorted(members)); channel["key_epoch"]=channel.get("key_epoch",1)+1; return channel

    def delete_channel(self, actor: str, admins: set[str], channel_id: str) -> None:
        if actor not in admins: raise PermissionError("admin_required")
        if channel_id in {"public","announcements"}: raise ValueError("default_channel")
        if channel_id not in self.data["channels"]: raise KeyError("channel_not_found")
        self.data["channels"].pop(channel_id)
        for mid in [mid for mid,msg in self.data["messages"].items() if msg["channel_id"]==channel_id]: self.data["messages"].pop(mid)
        self.purge_channel_metadata(channel_id)

    def purge_channel_metadata(self, channel_id: str) -> None:
        self.data.get("keys", {}).pop(channel_id, None)
        self.data.get("key_commitments", {}).pop(channel_id, None)
        self.data["key_requests"] = {rid: request for rid, request in self.data.get("key_requests", {}).items() if request.get("channel_id") != channel_id}
        for seen in self.data.get("seen", {}).values():
            if isinstance(seen, dict):
                seen.pop(channel_id, None)
        for user_id, channels in self.data.get("silenced", {}).items():
            if isinstance(channels, list):
                self.data["silenced"][user_id] = [item for item in channels if item != channel_id]

    def set_user_allowed(self, actor: str, admins: set[str], user_id: str, allowed: bool) -> None:
        if actor not in admins: raise PermissionError("admin_required")
        if user_id == actor and not allowed: raise ValueError("cannot_disable_self")
        current=self.data["users"].get("allowed")
        current=set(current) if current is not None else set()
        if allowed: current.add(user_id)
        else: current.discard(user_id)
        self.data["users"]["allowed"]=sorted(current)

    def set_members(self, actor: str, admins: set[str], channel_id: str, members: set[str]) -> None:
        if actor not in admins: raise PermissionError("admin_required")
        if channel_id not in self.data["channels"]: raise KeyError("channel_not_found")
        self.data["channels"][channel_id]["members"] = sorted(members)
        self.data["channels"][channel_id]["key_epoch"] = self.data["channels"][channel_id].get("key_epoch", 1) + 1

    def resolve_private(self, actor: str, handle: str, users: list[dict[str, Any]], enabled: set[str], confirm_unblock: bool) -> dict[str, Any]:
        if not isinstance(handle, str) or not HANDLE_RE.match(handle): raise ValueError("invalid_handle")
        number,_ = self.parse_identity(handle)
        matches = [u for u in users if u.get("enabled") and u.get("id") in enabled and u.get("id") != actor and ((number and self.ensure_identity(u["id"]) == number) or (not number and u.get("name") == handle))]
        if len(matches) != 1: raise ValueError("invalid_handle")
        target = matches[0]["id"]; own = set(self.data["blocks"].get(actor, [])); own_block = target in own
        if own_block and not confirm_unblock: raise PermissionError("confirm_unblock")
        if own_block: own.discard(target); self.data["blocks"][actor] = sorted(own)
        if actor in self.data["blocks"].get(target, []): raise PermissionError("blocked_by_other")
        members = {actor, target}
        existing = next((channel for channel in self.data["channels"].values() if channel.get("kind") == "private" and set(channel.get("members", [])) == members), None)
        cid = existing["id"] if existing else new_id("dm")
        self.data["channels"].setdefault(cid, {"id":cid,"kind":"private","name":"Private chat","restricted":True,"members":sorted((actor,target)),"key_epoch":1})
        return {"channel":self.data["channels"][cid],"user":{"id":target,"identity":str(self.ensure_identity(target)),"name":handle},"unblocked":own_block}

    def add_block(self, actor: str, target: str) -> None:
        blocks=set(self.data["blocks"].get(actor, [])); blocks.add(target); self.data["blocks"][actor]=sorted(blocks)
        members={actor,target}
        for channel in self.data["channels"].values():
            if channel.get("kind") == "private" and set(channel.get("members", [])) == members:
                channel["key_epoch"] = channel.get("key_epoch",1)+1
    def remove_block(self, actor: str, target: str) -> None: self.data["blocks"][actor]=sorted(set(self.data["blocks"].get(actor, []))-{target})
    def private_blocked(self, a: str, b: str) -> bool: return b in self.data["blocks"].get(a, []) or a in self.data["blocks"].get(b, [])
    def set_private_silenced(self, actor: str, channel_id: str, silenced: bool) -> None:
        channel=self.data["channels"].get(channel_id)
        if not channel or channel.get("kind") != "private" or actor not in channel.get("members",[]): raise PermissionError("channel_access")
        channels=set(self.data["silenced"].get(actor,[]))
        if silenced: channels.add(channel_id)
        else: channels.discard(channel_id)
        self.data["silenced"][actor]=sorted(channels)

    def add_message(self, actor: str, channel_id: str, ciphertext: str, envelope: dict[str, Any], admins: set[str], now: float | None = None) -> dict[str, Any]:
        if not self.can_post(channel_id, actor, admins): raise PermissionError("channel_access")
        validate_envelope(ciphertext, envelope)
        commitment=envelope.get("key_commitment"); key_id=envelope.get("key_id")
        if commitment is None: commitment = ""
        if commitment and (not isinstance(commitment,str) or not re.fullmatch(r"[A-Za-z0-9+/]{43}=",commitment)): raise ValueError("invalid_key_commitment")
        channel=self.data["channels"][channel_id]
        if key_id != f"{channel_id}:{channel.get('key_epoch',1)}": raise ValueError("invalid_key_id")
        try: aad = _decode_standard_b64(envelope["aad"], field="aad").decode("utf-8")
        except (UnicodeDecodeError, ValueError) as err: raise ValueError("invalid_aad") from err
        if aad != channel_id: raise ValueError("invalid_aad")
        device_id=envelope["device_id"]
        if device_id not in self.data["devices"].get(actor, {}): raise ValueError("unknown_device")
        if envelope["counter"] <= self.data["replay"].get(device_id, 0): raise ValueError("replayed_message")
        committed=self.data["key_commitments"].get(channel_id,{}).get(key_id)
        if commitment:
            if committed and committed != commitment: raise ValueError("key_commitment_conflict")
            self.data["key_commitments"].setdefault(channel_id,{})[key_id]=commitment
        elif committed: raise ValueError("key_commitment_required")
        self.data["replay"][device_id] = envelope["counter"]
        message_id=new_id("message")
        msg={"id":message_id,"channel_id":channel_id,"sender_id":actor,"origin_server_id":self.data["server_id"],"protocol_version":PROTOCOL_VERSION,"ciphertext":ciphertext,"envelope":envelope,"created":now or time.time(),"deleted":False}
        self.data["messages"][message_id]=msg; return msg
    def delete_message(self, actor: str, message_id: str, admins: set[str], keep_marker: bool = True) -> None:
        msg=self.data["messages"].get(message_id)
        if not msg: raise KeyError("message_not_found")
        if msg["sender_id"] != actor: raise PermissionError("message_access")
        if keep_marker: msg.update(deleted=True, ciphertext="", envelope={})
        else: self.data["messages"].pop(message_id)
    def delete_private(self, actor: str, channel_id: str, confirm: bool) -> None:
        channel=self.data["channels"].get(channel_id)
        if not channel or channel["kind"] != "private" or actor not in channel["members"]: raise PermissionError("channel_access")
        if not confirm: raise PermissionError("confirm_delete")
        self.data["channels"].pop(channel_id)
        for mid in [mid for mid,msg in self.data["messages"].items() if msg["channel_id"] == channel_id]: self.data["messages"].pop(mid)
        self.purge_channel_metadata(channel_id)
    def set_mute(self, actor: str, target: str, muted: bool, admins: set[str]) -> None:
        if actor not in admins: raise PermissionError("admin_required")
        self.data["mutes"][target]=muted
    def mark_seen(self, user_id: str, channel_id: str, message_id: str) -> None: self.data["seen"].setdefault(user_id,{})[channel_id]=message_id
    def register_device(self, user_id: str, device_id: str, public_key: str, label: str = "") -> dict[str, Any]:
        try: parsed_id=uuid.UUID(device_id)
        except (ValueError,TypeError,AttributeError) as err: raise ValueError("invalid_device") from err
        if str(parsed_id)!=device_id or parsed_id.version!=4 or not public_key or len(public_key)>2048 or len(label)>80: raise ValueError("invalid_device")
        key = _public_jwk(public_key)
        if len(self.data["devices"].get(user_id,{})) >= MAX_DEVICES_PER_USER and device_id not in self.data["devices"].get(user_id,{}): raise ValueError("device_limit")
        existing_owner=next((owner for owner,devices in self.data["devices"].items() if device_id in devices),None)
        if existing_owner not in (None,user_id): raise ValueError("device_id_in_use")
        existing = self.data["devices"].get(user_id,{}).get(device_id)
        if existing and existing.get("public_key") != public_key: raise ValueError("device_key_conflict")
        device = {"id":device_id,"user_id":user_id,"public_key":public_key,"label":label[:80],"last_seen":time.time()}
        self.data["devices"].setdefault(user_id,{})[device_id] = device
        return {k:v for k,v in device.items() if k != "public_key"}
    def offer_key(self, actor: str, channel_id: str, device_id: str, key_id: str, wrapped_key: str, admins: set[str], key_commitment: str = "") -> None:
        if not self.can_view(channel_id, actor, admins): raise PermissionError("channel_access")
        if not all(isinstance(x,str) and x for x in (device_id,key_id,wrapped_key)) or len(wrapped_key)>MAX_WRAPPED_OFFER: raise ValueError("invalid_key_offer")
        channel = self.data["channels"][channel_id]
        if key_id != f"{channel_id}:{channel.get('key_epoch', 1)}": raise ValueError("invalid_key_offer")
        if not isinstance(key_commitment, str) or (key_commitment and not re.fullmatch(r"[A-Za-z0-9+/]{43}=",key_commitment)): raise ValueError("invalid_key_offer")
        committed=self.data.get("key_commitments",{}).get(channel_id,{}).get(key_id)
        if committed and (not key_commitment or key_commitment != committed): raise ValueError("key_commitment_conflict")
        target_owner = next((uid for uid, devices in self.data["devices"].items() if device_id in devices), None)
        if target_owner is None or not self.can_view(channel_id, target_owner, admins): raise ValueError("invalid_key_offer")
        try:
            wrapped=json.loads(wrapped_key)
            if not isinstance(wrapped, dict) or set(wrapped)!={"nonce","ciphertext","sender_public","sender_device_id"} or not isinstance(wrapped["sender_public"],dict): raise ValueError
            sender_id=wrapped["sender_device_id"]
            parsed_sender=uuid.UUID(sender_id)
            if str(parsed_sender) != sender_id or parsed_sender.version != 4: raise ValueError
            sender=self.data["devices"].get(actor,{}).get(sender_id)
            if not sender or wrapped["sender_public"] != json.loads(sender["public_key"]): raise ValueError
            nonce=_decode_standard_b64(wrapped["nonce"],field="key_offer",max_decoded=12); ciphertext=_decode_standard_b64(wrapped["ciphertext"],field="key_offer",max_decoded=4096)
            if len(nonce)!=12 or not 16<=len(ciphertext)<=4096: raise ValueError
            if wrapped["sender_public"] != json.loads(sender["public_key"]): raise ValueError
        except (ValueError,TypeError,KeyError,json.JSONDecodeError,base64.binascii.Error,AttributeError) as err: raise ValueError("invalid_key_offer") from err
        sender_id = wrapped["sender_device_id"]
        offer = {"device_id":device_id,"wrapped_key":wrapped_key,"key_commitment":key_commitment,"from_device":actor,"from_device_id":sender_id}
        sender_offers = self.data["keys"].setdefault(channel_id,{}).setdefault(key_id,{}).setdefault(device_id,{})
        existing = sender_offers.get(sender_id)
        if existing is not None:
            if existing == offer:
                for request_id in [rid for rid, request in self.data["key_requests"].items() if request.get("channel_id")==channel_id and request.get("device_id")==device_id]: self.data["key_requests"].pop(request_id,None)
                return
            raise ValueError("key_offer_conflict")
        sender_offers[sender_id] = offer
        for request_id in [rid for rid, request in self.data["key_requests"].items() if request.get("channel_id")==channel_id and request.get("device_id")==device_id]: self.data["key_requests"].pop(request_id,None)
    def key_state(self, user_id: str, channel_id: str, admins: set[str] | None = None) -> dict[str, Any]:
        if not self.can_view(channel_id, user_id, admins or set()): raise PermissionError("channel_access")
        devices = self.data["devices"].get(user_id,{})
        offers = self.data["keys"].get(channel_id,{})
        own_ids=set(devices)
        channel = self.data["channels"][channel_id]
        participant_ids = channel["members"] if channel["restricted"] else list(self.data["devices"])
        device_count = sum(len(self.data["devices"].get(uid, {})) for uid in participant_ids)
        key_id=f"{channel_id}:{channel.get('key_epoch',1)}"
        commitments=dict(self.data.get("key_commitments",{}).get(channel_id,{}))
        participant_ids = channel["members"] if channel["restricted"] else list(self.data["devices"])
        channel_device_ids={device_id for participant_id in participant_ids for device_id in self.data["devices"].get(participant_id,{})}
        pending=[{field: request[field] for field in ("id","channel_id","device_id","created") if field in request} for request in self.data["key_requests"].values() if request.get("channel_id")==channel_id and request.get("device_id") in channel_device_ids]
        flat_offers = []
        for offer_key_id, targets in offers.items():
            if not isinstance(targets, dict):
                continue
            for target_id, sender_offers in targets.items():
                if target_id not in own_ids or not isinstance(sender_offers, dict):
                    continue
                for offer in sender_offers.values():
                    if isinstance(offer, dict):
                        flat_offers.append({**offer, "key_id": offer_key_id})
        return {"state":"ready" if flat_offers else "waiting_for_device","device_count":device_count,"commitment":commitments.get(key_id),"commitments":commitments,"pending_requests":pending,"offers":flat_offers}
    def reset_channel_key(self, actor: str, channel_id: str, device_id: str, expected_epoch: int, admins: set[str] | None = None) -> int:
        if not self.can_view(channel_id,actor,admins or set()): raise PermissionError("channel_access")
        channel=self.data["channels"][channel_id]
        if device_id not in self.data["devices"].get(actor,{}): raise PermissionError("device_access")
        if expected_epoch != channel.get("key_epoch",1): raise ValueError("stale_key_epoch")
        requests=[request_id for request_id,request in self.data["key_requests"].items() if request.get("user_id")==actor and request.get("device_id")==device_id and request.get("channel_id")==channel_id]
        if not requests: raise PermissionError("key_recovery_not_requested")
        channel["key_epoch"]=expected_epoch+1
        for request_id in requests: self.data["key_requests"].pop(request_id,None)
        return channel["key_epoch"]
    def security_code(self, channel_id: str) -> str: return hashlib.sha256(f"{self.data['server_id']}:{channel_id}:{self.data['channels'].get(channel_id,{}).get('key_epoch',1)}".encode()).hexdigest()[:12].upper()
    def request_key(self, user_id: str, channel_id: str, device_id: str) -> dict[str, Any]:
        for request in self.data["key_requests"].values():
            if request.get("user_id")==user_id and request.get("channel_id")==channel_id and request.get("device_id")==device_id: return request
        if sum(1 for request in self.data["key_requests"].values() if request.get("user_id")==user_id and request.get("channel_id")==channel_id and request.get("device_id")==device_id) >= MAX_PENDING_KEY_REQUESTS_PER_DEVICE_CHANNEL:
            raise ValueError("key_request_limit")
        if sum(1 for request in self.data["key_requests"].values() if request.get("user_id") == user_id) >= MAX_PENDING_KEY_REQUESTS_PER_USER:
            raise ValueError("key_request_limit")
        if len(self.data["key_requests"]) >= MAX_PENDING_KEY_REQUESTS:
            raise ValueError("key_request_limit")
        request={"id":new_id("keyreq"),"user_id":user_id,"device_id":device_id,"channel_id":channel_id,"created":time.time()}; self.data["key_requests"][request["id"]]=request; return request
    def revoke_device(self, actor: str, device_id: str, admins: set[str]) -> None:
        for uid, devices in self.data["devices"].items():
            if device_id in devices:
                if actor != uid and actor not in admins: raise PermissionError("device_access")
                devices.pop(device_id)
                self.data.get("replay", {}).pop(device_id, None)
                self.data["key_requests"] = {rid: request for rid, request in self.data.get("key_requests", {}).items() if request.get("device_id") != device_id}
                for channel_keys in self.data.get("keys", {}).values():
                    for targets in channel_keys.values():
                        for target_id in list(targets):
                            sender_offers = targets[target_id]
                            if isinstance(sender_offers, dict) and "wrapped_key" in sender_offers:
                                if target_id == device_id or sender_offers.get("from_device_id") == device_id: targets.pop(target_id, None)
                            elif isinstance(sender_offers, dict):
                                for sender_id, offer in list(sender_offers.items()):
                                    if target_id == device_id or sender_id == device_id or (isinstance(offer, dict) and offer.get("from_device_id") == device_id): sender_offers.pop(sender_id, None)
                            if not targets.get(target_id): targets.pop(target_id, None)
                for channel in self.data["channels"].values():
                    if uid in channel.get("members",[]) or not channel.get("restricted",False): channel["key_epoch"]=channel.get("key_epoch",1)+1
                return
        raise KeyError("device_not_found")
    def devices_for_channel(self, user_id: str, channel_id: str, admins: set[str] | None = None) -> list[dict[str, Any]]:
        channel = self.data["channels"].get(channel_id)
        if not self.can_view(channel_id,user_id,admins or set()): raise PermissionError("channel_access")
        user_ids = channel["members"] if channel["restricted"] else list(self.data["devices"])
        return [device for uid in user_ids for device in self.data["devices"].get(uid, {}).values()]
