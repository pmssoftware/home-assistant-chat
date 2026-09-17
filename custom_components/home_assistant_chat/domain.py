"""Transport-independent chat rules and serializable state."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any

from .const import MAX_MESSAGE_LENGTH, PROTOCOL_VERSION

HANDLE_RE = re.compile(r"^.{1,128}$", re.DOTALL)

def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"

def validate_envelope(ciphertext: Any, envelope: Any) -> None:
    if not isinstance(ciphertext, str) or not ciphertext or len(ciphertext) > MAX_MESSAGE_LENGTH * 4:
        raise ValueError("invalid_ciphertext")
    if not isinstance(envelope, dict): raise ValueError("invalid_envelope")
    required = ("version", "device_id", "counter", "nonce", "key_id", "aad")
    if any(key not in envelope for key in required) or envelope["version"] != PROTOCOL_VERSION:
        raise ValueError("invalid_envelope")
    if not isinstance(envelope["device_id"], str) or not envelope["device_id"] or not isinstance(envelope["key_id"], str):
        raise ValueError("invalid_envelope")
    if not isinstance(envelope["counter"], int) or envelope["counter"] < 1: raise ValueError("invalid_counter")
    try: base64.b64decode(ciphertext, validate=True)
    except (ValueError, TypeError, base64.binascii.Error) as err: raise ValueError("invalid_ciphertext") from err
    for key in ("nonce", "aad"):
        try: raw = base64.b64decode(envelope[key], validate=True)
        except (ValueError, TypeError, base64.binascii.Error) as err: raise ValueError("invalid_envelope") from err
        if key == "nonce" and len(raw) != 12: raise ValueError("invalid_nonce")

@dataclass(slots=True)
class ChatDomain:
    data: dict[str, Any]

    @classmethod
    def fresh(cls, server_id: str | None = None) -> "ChatDomain":
        sid = server_id or new_id("server")
        return cls({"schema_version": 2, "server_id": sid, "channels": {
            "public": {"id":"public","kind":"public","name":"Public chat","restricted":False,"members":[],"key_epoch":1},
            "announcements": {"id":"announcements","kind":"announcement","name":"Announcements","restricted":True,"members":[],"key_epoch":1},
        }, "messages": {}, "blocks": {}, "mutes": {}, "devices": {}, "keys": {}, "key_requests": {}, "seen": {}, "replay": {}, "users": {"allowed": None}})

    def migrate(self) -> bool:
        changed = False; version = self.data.get("schema_version", 0); defaults = self.fresh(self.data.get("server_id")).data
        for key, value in defaults.items():
            if key not in self.data: self.data[key] = value; changed = True
        if version < 2: self.data["schema_version"] = 2; changed = True
        return changed

    def can_access(self, user_id: str, globally_enabled: bool, allowed_users: set[str] | None) -> bool:
        return globally_enabled and (allowed_users is None or user_id in allowed_users)

    def channels_for(self, user_id: str, admins: set[str], globally_enabled: bool, allowed_users: set[str] | None, include_members: bool = False) -> list[dict[str, Any]]:
        if not self.can_access(user_id, globally_enabled, allowed_users): return []
        return [dict(ch) if include_members and user_id in admins else {k:v for k,v in ch.items() if k != "members"} for ch in self.data["channels"].values() if (ch["kind"] == "private" and user_id in ch["members"] and not self.private_blocked(*ch["members"])) or (ch["kind"] == "announcement") or (ch["kind"] != "private" and ch["kind"] != "announcement" and (not ch["restricted"] or user_id in ch["members"] or user_id in admins))]

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
        if channel["kind"] == "announcement": return True
        if channel["kind"] == "private": return user_id in channel["members"] and not self.private_blocked(*channel["members"])
        return not channel["restricted"] or user_id in channel["members"] or user_id in admins

    def add_channel(self, actor: str, admins: set[str], name: str, kind: str, restricted: bool, members: set[str]) -> dict[str, Any]:
        if actor not in admins: raise PermissionError("admin_required")
        if kind not in {"public", "group", "announcement"} or not name.strip(): raise ValueError("invalid_channel")
        channel = {"id":new_id("channel"),"kind":kind,"name":name.strip()[:80],"restricted":restricted,"members":sorted(members),"key_epoch":1}
        self.data["channels"][channel["id"]] = channel; return channel

    def edit_channel(self, actor: str, admins: set[str], channel_id: str, name: str, restricted: bool, members: set[str]) -> dict[str, Any]:
        if actor not in admins: raise PermissionError("admin_required")
        channel=self.data["channels"].get(channel_id)
        if not channel or channel_id in {"public","announcements"} and channel["kind"] in {"public","announcement"} and not name.strip(): raise ValueError("invalid_channel")
        if not channel: raise KeyError("channel_not_found")
        channel.update(name=name.strip()[:80],restricted=restricted,members=sorted(members)); channel["key_epoch"]=channel.get("key_epoch",1)+1; return channel

    def delete_channel(self, actor: str, admins: set[str], channel_id: str) -> None:
        if actor not in admins: raise PermissionError("admin_required")
        if channel_id in {"public","announcements"}: raise ValueError("default_channel")
        if channel_id not in self.data["channels"]: raise KeyError("channel_not_found")
        self.data["channels"].pop(channel_id)
        for mid in [mid for mid,msg in self.data["messages"].items() if msg["channel_id"]==channel_id]: self.data["messages"].pop(mid)

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
        matches = [u for u in users if u.get("enabled") and u.get("id") in enabled and u.get("name") == handle and u.get("id") != actor]
        if len(matches) != 1: raise ValueError("invalid_handle")
        target = matches[0]["id"]; own = set(self.data["blocks"].get(actor, [])); own_block = target in own
        if own_block and not confirm_unblock: raise PermissionError("confirm_unblock")
        if own_block: own.discard(target); self.data["blocks"][actor] = sorted(own)
        if actor in self.data["blocks"].get(target, []): raise PermissionError("blocked_by_other")
        cid = "dm_" + "_".join(sorted((actor, target)))
        self.data["channels"].setdefault(cid, {"id":cid,"kind":"private","name":"Private chat","restricted":True,"members":sorted((actor,target)),"key_epoch":1})
        return {"channel":self.data["channels"][cid],"user":{"id":target,"name":handle,"avatar_url":f"/api/config/avatar/{target}"},"unblocked":own_block}

    def add_block(self, actor: str, target: str) -> None:
        blocks=set(self.data["blocks"].get(actor, [])); blocks.add(target); self.data["blocks"][actor]=sorted(blocks)
        cid="dm_"+"_".join(sorted((actor,target)))
        if cid in self.data["channels"]: self.data["channels"][cid]["key_epoch"] = self.data["channels"][cid].get("key_epoch",1)+1
    def remove_block(self, actor: str, target: str) -> None: self.data["blocks"][actor]=sorted(set(self.data["blocks"].get(actor, []))-{target})
    def private_blocked(self, a: str, b: str) -> bool: return b in self.data["blocks"].get(a, []) or a in self.data["blocks"].get(b, [])

    def add_message(self, actor: str, channel_id: str, ciphertext: str, envelope: dict[str, Any], admins: set[str], now: float | None = None) -> dict[str, Any]:
        if not self.can_post(channel_id, actor, admins): raise PermissionError("channel_access")
        validate_envelope(ciphertext, envelope)
        device_id=envelope["device_id"]
        if device_id not in self.data["devices"].get(actor, {}): raise ValueError("unknown_device")
        if envelope["counter"] <= self.data["replay"].get(device_id, 0): raise ValueError("replayed_message")
        self.data["replay"][device_id] = envelope["counter"]
        message_id=new_id("message")
        msg={"id":message_id,"channel_id":channel_id,"sender_id":actor,"origin_server_id":self.data["server_id"],"protocol_version":PROTOCOL_VERSION,"ciphertext":ciphertext,"envelope":envelope,"created":now or time.time(),"deleted":False}
        self.data["messages"][message_id]=msg; return msg
    def delete_message(self, actor: str, message_id: str, admins: set[str]) -> None:
        msg=self.data["messages"].get(message_id)
        if not msg: raise KeyError("message_not_found")
        if msg["sender_id"] != actor and actor not in admins: raise PermissionError("message_access")
        msg.update(deleted=True, ciphertext="")
    def delete_private(self, actor: str, channel_id: str, confirm: bool) -> None:
        channel=self.data["channels"].get(channel_id)
        if not channel or channel["kind"] != "private" or actor not in channel["members"]: raise PermissionError("channel_access")
        if not confirm: raise PermissionError("confirm_delete")
        self.data["channels"].pop(channel_id)
        for mid in [mid for mid,msg in self.data["messages"].items() if msg["channel_id"] == channel_id]: self.data["messages"].pop(mid)
    def set_mute(self, actor: str, target: str, muted: bool, admins: set[str]) -> None:
        if actor not in admins: raise PermissionError("admin_required")
        self.data["mutes"][target]=muted
    def mark_seen(self, user_id: str, channel_id: str, message_id: str) -> None: self.data["seen"].setdefault(user_id,{})[channel_id]=message_id
    def register_device(self, user_id: str, device_id: str, public_key: str, label: str = "") -> dict[str, Any]:
        if not device_id or len(device_id) > 128 or not public_key: raise ValueError("invalid_device")
        device = {"id":device_id,"user_id":user_id,"public_key":public_key,"label":label[:80],"last_seen":time.time()}
        self.data["devices"].setdefault(user_id,{})[device_id] = device
        return {k:v for k,v in device.items() if k != "public_key"}
    def offer_key(self, actor: str, channel_id: str, device_id: str, key_id: str, wrapped_key: str, admins: set[str]) -> None:
        if not self.can_view(channel_id, actor, admins): raise PermissionError("channel_access")
        if not all(isinstance(x,str) and x for x in (device_id,key_id,wrapped_key)): raise ValueError("invalid_key_offer")
        try: wrapped=json.loads(wrapped_key)
        except (TypeError,ValueError) as err: raise ValueError("invalid_key_offer") from err
        if wrapped.get("sender_device_id") not in self.data["devices"].get(actor,{}): raise ValueError("invalid_key_offer")
        self.data["keys"].setdefault(channel_id,{}).setdefault(key_id,{})[device_id] = {"device_id":device_id,"wrapped_key":wrapped_key,"from_device":actor,"from_device_id":wrapped["sender_device_id"]}
    def key_state(self, user_id: str, channel_id: str) -> dict[str, Any]:
        devices = self.data["devices"].get(user_id,{})
        offers = self.data["keys"].get(channel_id,{})
        own_ids=set(devices); available=[device_id for key in offers.values() for device_id in key if device_id in own_ids]
        return {"state":"ready" if available else "waiting_for_device","device_count":len(devices),"security_code":self.security_code(channel_id) if self.data["channels"].get(channel_id,{}).get("show_security_details") else None,"offers":{key_id:{device_id:{**offer,"key_id":key_id} for device_id,offer in group.items() if device_id in own_ids} for key_id,group in offers.items()}}
    def security_code(self, channel_id: str) -> str: return hashlib.sha256(f"{self.data['server_id']}:{channel_id}:{self.data['channels'].get(channel_id,{}).get('key_epoch',1)}".encode()).hexdigest()[:12].upper()
    def request_key(self, user_id: str, channel_id: str, device_id: str) -> dict[str, Any]:
        request={"id":new_id("keyreq"),"user_id":user_id,"device_id":device_id,"channel_id":channel_id,"created":time.time()}; self.data["key_requests"][request["id"]]=request; return request
    def revoke_device(self, actor: str, device_id: str, admins: set[str]) -> None:
        for uid, devices in self.data["devices"].items():
            if device_id in devices:
                if actor != uid and actor not in admins: raise PermissionError("device_access")
                devices.pop(device_id)
                for channel in self.data["channels"].values():
                    if uid in channel.get("members",[]) or not channel.get("restricted",False): channel["key_epoch"]=channel.get("key_epoch",1)+1
                return
        raise KeyError("device_not_found")
    def devices_for_channel(self, user_id: str, channel_id: str, admins: set[str] | None = None) -> list[dict[str, Any]]:
        channel = self.data["channels"].get(channel_id)
        if not self.can_view(channel_id,user_id,admins or set()): raise PermissionError("channel_access")
        user_ids = channel["members"] if channel["restricted"] else list(self.data["devices"])
        return [device for uid in user_ids for device in self.data["devices"].get(uid, {}).values() if device["user_id"] != user_id]
