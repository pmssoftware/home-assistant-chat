from __future__ import annotations

import re
from typing import Any
import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback

from .const import DOMAIN, PROTOCOL_VERSION
from .domain import normalize_federation_endpoint

MESSAGE_PAGE_SIZE = 100
CURSOR_RE = re.compile(r"^(\d+(?:\.\d+)?):([A-Za-z0-9_-]+)$")

def _store(hass: HomeAssistant): return next(iter(hass.data[DOMAIN].values()))
def _uid(connection) -> str: return connection.user.id
def _admins(connection) -> set[str]: return {_uid(connection)} if connection.user and connection.user.is_admin else set()
def _result(connection, msg_id, value=None): connection.send_result(msg_id, value)
def _error(connection, msg_id, code): connection.send_error(msg_id, code, code)
def _require_access(store, connection, msg_id) -> bool:
    if not store.can_use(_uid(connection), bool(connection.user and connection.user.is_admin)): _error(connection,msg_id,"chat_disabled"); return False
    return True
async def _members(hass, raw: list[str]) -> set[str]:
    known={u.id for u in await hass.auth.async_get_users()}
    if not set(raw) <= known: raise ValueError("invalid_member")
    return set(raw)

def _message_page(store, channel_id: str, names: dict[str, str], show_deleted: bool, before: str | None = None) -> dict[str, Any]:
    def sort_key(message):
        try: created=float(message.get("created", 0))
        except (TypeError, ValueError): created=0.0
        return (created, str(message.get("id", "")))
    cursor = None
    if before is not None:
        match = CURSOR_RE.fullmatch(before)
        if not match: raise ValueError("invalid_history_cursor")
        cursor = (float(match.group(1)), match.group(2))
    messages = [message for message in store.data["messages"].values() if isinstance(message, dict) and message.get("channel_id") == channel_id and (not message.get("deleted") or show_deleted)]
    messages.sort(key=sort_key)
    if cursor is not None:
        messages = [message for message in messages if sort_key(message) < cursor]
    page = messages[-MESSAGE_PAGE_SIZE:]
    result = [{**message, "sender_name": names.get(message.get("sender_id"), "User")} for message in page]
    oldest = page[0] if page else None
    return {"messages":result,"has_older_messages":bool(messages and oldest and len(messages) > len(page)),"oldest_cursor":f"{sort_key(oldest)[0]}:{oldest.get('id')}" if oldest else None}

def async_register_websocket(hass: HomeAssistant, store) -> None:
    if hass.data.setdefault(f"{DOMAIN}_ws_registered", False): return
    hass.data[f"{DOMAIN}_ws_registered"] = True
    for handler in (_state,_history,_subscribe,_send,_private,_channel_create,_channel_edit,_channel_delete,_channel_members,_message_delete,_private_delete,_private_silence,_block,_blocked_users,_unblock,_mute,_seen,_users,_user_access,_device_register,_device_list,_device_revoke,_key_offer,_key_state,_key_states,_key_devices,_key_request,_key_reset,_recovery_get,_recovery_set,_settings): websocket_api.async_register_command(hass, handler)

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/state", vol.Optional("channel_id"): str})
@websocket_api.async_response
async def _state(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    uid=_uid(connection); admins=_admins(connection); settings=store.settings()
    channels=store.domain.channels_for(uid,admins,settings["enabled"],store.data["users"].get("allowed"),include_members=bool(admins))
    users=await hass.auth.async_get_users(); names={u.id:u.name for u in users}
    own_identity=store.domain.ensure_identity(uid); identities_changed=False
    for user in users:
        before=user.id in store.domain.data["identities"]; store.domain.ensure_identity(user.id); identities_changed |= not before
    if identities_changed: await store.async_save()
    for channel in channels:
        source=store.data["channels"].get(channel["id"],{})
        if source.get("kind")=="private":
            peer_id=next((member for member in source.get("members",[]) if member!=uid),None)
            channel["peer"]={"id":peer_id,"name":names.get(peer_id,"User"),"identity":str(store.domain.ensure_identity(peer_id)),"identity_address":store.identity_address(peer_id)} if peer_id else None
            channel["silenced"]=channel["id"] in store.data["silenced"].get(uid,[])
    visible={c["id"] for c in channels}; requested=msg.get("channel_id"); active_channel=requested if requested in visible else (channels[0]["id"] if channels else None)
    page=_message_page(store,active_channel,names,settings["show_deleted_messages"]) if active_channel else {"messages":[],"has_older_messages":False,"oldest_cursor":None}
    key_states={}
    for channel in channels:
        try: key_states[channel["id"]]=store.domain.key_state(uid,channel["id"],admins)
        except PermissionError: continue
    devices=[]
    source=store.data["devices"].items() if admins else [(uid,store.data["devices"].get(uid,{}))]
    for owner, owned in source:
        for device in owned.values(): devices.append({k:v for k,v in device.items() if admins or k != "public_key"})
    _result(connection,msg["id"],{"protocol_version":PROTOCOL_VERSION,"server_id":store.data["server_id"],"user_id":uid,"identity":str(own_identity),"identity_address":store.identity_address(uid),"channels":channels,"messages":page["messages"],"has_older_messages":page["has_older_messages"],"oldest_cursor":page["oldest_cursor"],"key_states":key_states,"devices":devices,"seen":store.data["seen"].get(uid,{}),"is_admin":bool(admins),"is_muted":bool(store.data["mutes"].get(uid)),"settings":{"enabled":settings["enabled"],"allow_users":settings["allow_users"],"retention_days":settings["retention_days"],"show_security_details":settings["show_security_details"],"show_deleted_messages":settings["show_deleted_messages"],"federation_qr_enabled":settings["federation_qr_enabled"],"federation_address":settings["federation_address"],"federation_port":settings["federation_port"]}})

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/history", vol.Required("channel_id"): str, vol.Optional("before"): str})
@websocket_api.async_response
async def _history(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    uid=_uid(connection); admins=_admins(connection); settings=store.settings()
    if not store.domain.can_view(msg["channel_id"],uid,admins): _error(connection,msg["id"],"channel_access"); return
    names={user.id:user.name for user in await hass.auth.async_get_users()}
    try: result=_message_page(store,msg["channel_id"],names,settings["show_deleted_messages"],msg.get("before"))
    except ValueError as err: _error(connection,msg["id"],str(err)); return
    _result(connection,msg["id"],result)

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/subscribe", vol.Optional("channel_id"): str})
@websocket_api.async_response
async def _subscribe(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    uid=_uid(connection); channel_id=msg.get("channel_id"); is_admin=bool(connection.user and connection.user.is_admin)
    def listener(event):
        if not store.can_use(uid,is_admin): return
        message=event.get("message",{}); event_channel=message.get("channel_id") or event.get("channel_id") or event.get("request",{}).get("channel_id") or event.get("channel",{}).get("id")
        visible={c["id"] for c in store.domain.channels_for(uid,_admins(connection),store.settings()["enabled"],store.data["users"].get("allowed"))}
        recipients=set(event.get("user_ids",[])); user_event=event.get("user_id")==uid or uid in recipients or bool(_admins(connection))
        allowed=event.get("global") is True or user_event or (event_channel in visible and (not channel_id or channel_id == event_channel))
        if allowed:
            safe_event={key:value for key,value in event.items() if key!="user_ids"}
            connection.send_event(msg["id"],safe_event)
    connection.subscriptions[msg["id"]]=store.subscribe(listener); _result(connection,msg["id"],{"subscribed":True})

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/send", vol.Required("channel_id"): str, vol.Required("ciphertext"): str, vol.Required("envelope"): dict})
@websocket_api.async_response
async def _send(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    uid=_uid(connection)
    try:
        store.check_rate(uid); result=store.domain.add_message(uid,msg["channel_id"],msg["ciphertext"],msg["envelope"],_admins(connection))
        await store.changed("message",message=result)
    except (PermissionError,ValueError,KeyError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"],{"message":result})

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/private", vol.Required("handle"): str, vol.Optional("confirm_unblock", default=False): bool})
@websocket_api.async_response
async def _private(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    users=[{"id":u.id,"name":u.name,"enabled":store.can_use(u.id,u.is_admin)} for u in await hass.auth.async_get_users()]
    changed=False
    for user in users:
        before=user["id"] in store.domain.data["identities"]; user["identity"]=str(store.domain.ensure_identity(user["id"])); changed |= not before
    if changed: await store.async_save()
    try:
        store.check_rate(_uid(connection))
        result=store.domain.resolve_private(_uid(connection),msg["handle"],users,{u["id"] for u in users if u["enabled"]},msg["confirm_unblock"])
        result["user"]["identity_address"] = store.identity_address(result["user"]["id"])
        await store.changed("private",channel=result["channel"])
    except (PermissionError,ValueError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"],result)

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/channel/create", vol.Required("name"): str, vol.Required("kind"): str, vol.Optional("restricted", default=True): bool, vol.Optional("members", default=[]): [str]})
@websocket_api.require_admin
@websocket_api.async_response
async def _channel_create(hass, connection, msg):
    store=_store(hass)
    try: result=store.domain.add_channel(_uid(connection),_admins(connection),msg["name"],msg["kind"],msg["restricted"],await _members(hass,msg["members"])); await store.changed("channel",channel=result)
    except (PermissionError,ValueError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"],{"channel":result})

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/channel/edit", vol.Required("channel_id"): str, vol.Required("name"): str, vol.Required("restricted"): bool, vol.Optional("members", default=[]): [str], vol.Optional("kind"): str})
@websocket_api.require_admin
@websocket_api.async_response
async def _channel_edit(hass, connection, msg):
    store=_store(hass)
    old_members=set(store.data["channels"].get(msg["channel_id"],{}).get("members",[]))
    try:
        result=store.domain.edit_channel(_uid(connection),_admins(connection),msg["channel_id"],msg["name"],msg["restricted"],await _members(hass,msg["members"]),msg.get("kind"))
        await store.changed("channel",channel_id=result["id"],user_ids=list(old_members|set(result.get("members",[]))))
    except (PermissionError,ValueError,KeyError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"],{"channel":result})

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/channel/delete", vol.Required("channel_id"): str})
@websocket_api.require_admin
@websocket_api.async_response
async def _channel_delete(hass, connection, msg):
    store=_store(hass)
    channel=store.data["channels"].get(msg["channel_id"],{}); recipients=set(channel.get("members",[]))
    if not channel.get("restricted",True): recipients={u.id for u in await hass.auth.async_get_users()}
    try: store.domain.delete_channel(_uid(connection),_admins(connection),msg["channel_id"]); await store.changed("channel_deleted",channel_id=msg["channel_id"],user_ids=list(recipients))
    except (PermissionError,ValueError,KeyError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"])

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/channel/members", vol.Required("channel_id"): str, vol.Required("members"): [str]})
@websocket_api.require_admin
@websocket_api.async_response
async def _channel_members(hass, connection, msg):
    store=_store(hass)
    try: store.domain.set_members(_uid(connection),_admins(connection),msg["channel_id"],await _members(hass,msg["members"])); await store.changed("channel",channel=store.data["channels"][msg["channel_id"]])
    except (PermissionError,KeyError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"])

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/message/delete", vol.Required("message_id"): str})
@websocket_api.async_response
async def _message_delete(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    channel_id=store.data["messages"].get(msg["message_id"],{}).get("channel_id")
    try: store.check_rate(_uid(connection)); store.domain.delete_message(_uid(connection),msg["message_id"],_admins(connection),store.settings()["show_deleted_messages"]); await store.changed("message_deleted",message_id=msg["message_id"],channel_id=channel_id)
    except (PermissionError,KeyError,ValueError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"])

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/private/delete", vol.Required("channel_id"): str, vol.Required("confirm"): bool})
@websocket_api.async_response
async def _private_delete(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    recipients=list(store.data["channels"].get(msg["channel_id"],{}).get("members",[]))
    try: store.check_rate(_uid(connection)); store.domain.delete_private(_uid(connection),msg["channel_id"],msg["confirm"]); await store.changed("private_deleted",channel_id=msg["channel_id"],user_ids=recipients)
    except (PermissionError,KeyError,ValueError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"])

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/private/silence", vol.Required("channel_id"): str, vol.Required("silenced"): bool})
@websocket_api.async_response
async def _private_silence(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    try: store.check_rate(_uid(connection)); store.domain.set_private_silenced(_uid(connection),msg["channel_id"],msg["silenced"]); await store.changed("private_silenced",channel_id=msg["channel_id"],user_ids=[_uid(connection)])
    except (PermissionError,ValueError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"],{"silenced":msg["silenced"]})

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/user/block", vol.Required("user_id"): str})
@websocket_api.async_response
async def _block(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    known={u.id for u in await hass.auth.async_get_users()}
    if msg["user_id"] not in known or msg["user_id"]==_uid(connection): _error(connection,msg["id"],"invalid_user"); return
    try:
        store.check_rate(_uid(connection)); store.domain.add_block(_uid(connection),msg["user_id"]); await store.changed("block",user_ids=[_uid(connection),msg["user_id"]]); _result(connection,msg["id"])
    except ValueError as err: _error(connection,msg["id"],str(err))

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/user/unblock", vol.Required("user_id"): str})
@websocket_api.async_response
async def _unblock(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    try:
        store.check_rate(_uid(connection)); store.domain.remove_block(_uid(connection),msg["user_id"]); await store.changed("unblock",user_id=msg["user_id"]); _result(connection,msg["id"])
    except ValueError as err: _error(connection,msg["id"],str(err))

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/user/blocked"})
@websocket_api.async_response
async def _blocked_users(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    blocked=set(store.data["blocks"].get(_uid(connection),[]))
    users=await hass.auth.async_get_users()
    _result(connection,msg["id"],[{"id":user.id,"name":user.name} for user in users if user.id in blocked])

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/admin/mute", vol.Required("user_id"): str, vol.Required("muted"): bool})
@websocket_api.require_admin
@websocket_api.async_response
async def _mute(hass, connection, msg):
    store=_store(hass); store.domain.set_mute(_uid(connection),msg["user_id"],msg["muted"],_admins(connection)); await store.changed("mute",user_id=msg["user_id"],muted=msg["muted"]); _result(connection,msg["id"])

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/seen", vol.Required("channel_id"): str, vol.Required("message_id"): str})
@websocket_api.async_response
async def _seen(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    message=store.data["messages"].get(msg["message_id"])
    if not message or message.get("channel_id")!=msg["channel_id"] or not store.domain.can_view(msg["channel_id"],_uid(connection),_admins(connection)): _error(connection,msg["id"],"channel_access"); return
    try:
        store.check_rate(_uid(connection)); store.domain.mark_seen(_uid(connection),msg["channel_id"],msg["message_id"]); await store.changed("seen",user_id=_uid(connection),channel_id=msg["channel_id"],message_id=msg["message_id"]); _result(connection,msg["id"])
    except ValueError as err: _error(connection,msg["id"],str(err))

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/users/list"})
@websocket_api.require_admin
@websocket_api.async_response
async def _users(hass, connection, msg):
    store=_store(hass); result=[]
    changed=False
    for user in await hass.auth.async_get_users():
        before=user.id in store.data["identities"]; result.append({"id":user.id,"identity":str(store.domain.ensure_identity(user.id)),"name":user.name,"enabled":store.can_use(user.id,user.is_admin),"muted":store.data["mutes"].get(user.id,False),"seen":store.data["seen"].get(user.id,{})}); changed |= not before
    if changed: await store.async_save()
    _result(connection,msg["id"],result)

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/user/access", vol.Required("user_id"): str, vol.Required("allowed"): bool})
@websocket_api.require_admin
@websocket_api.async_response
async def _user_access(hass, connection, msg):
    store=_store(hass)
    try:
        if store.data["users"].get("allowed") is None:
            store.data["users"]["allowed"]=[u.id for u in await hass.auth.async_get_users()]
        store.domain.set_user_allowed(_uid(connection),_admins(connection),msg["user_id"],msg["allowed"]); await store.changed("access",user_id=msg["user_id"])
    except PermissionError as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"])

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/device/register", vol.Required("device_id"): str, vol.Required("public_key"): str, vol.Optional("label", default=""): str})
@websocket_api.async_response
async def _device_register(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    try: store.check_rate(_uid(connection)); result=store.domain.register_device(_uid(connection),msg["device_id"],msg["public_key"],msg["label"]); await store.changed("device",device=result)
    except ValueError as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"],result)

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/device/list"})
@websocket_api.async_response
async def _device_list(hass, connection, msg):
    store=_store(hass); admins=_admins(connection); result=[]; names={u.id:u.name for u in await hass.auth.async_get_users()}
    if not _require_access(store,connection,msg["id"]): return
    source=store.data["devices"].items() if admins else [(_uid(connection),store.data["devices"].get(_uid(connection),{}))]
    for uid,devices in source:
        for device in devices.values(): result.append({**{k:v for k,v in device.items() if k != "public_key" or admins},"owner_name":names.get(uid,"User")})
    _result(connection,msg["id"],result)

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/device/revoke", vol.Required("device_id"): str})
@websocket_api.async_response
async def _device_revoke(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    owner=next((uid for uid,devices in store.data["devices"].items() if msg["device_id"] in devices),None)
    try: store.check_rate(_uid(connection)); store.domain.revoke_device(_uid(connection),msg["device_id"],_admins(connection)); await store.changed("device_revoked",device_id=msg["device_id"],user_ids=[owner] if owner else [])
    except (PermissionError,KeyError,ValueError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"])

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/key/offer", vol.Required("channel_id"): str, vol.Required("device_id"): str, vol.Required("key_id"): str, vol.Required("key_commitment"): str, vol.Required("wrapped_key"): str})
@websocket_api.async_response
async def _key_offer(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    try: store.check_rate(_uid(connection)); store.domain.offer_key(_uid(connection),msg["channel_id"],msg["device_id"],msg["key_id"],msg["wrapped_key"],_admins(connection),msg["key_commitment"]); await store.changed("key_offer",channel_id=msg["channel_id"])
    except (PermissionError,ValueError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"])

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/key/state", vol.Required("channel_id"): str})
@websocket_api.async_response
async def _key_state(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    if not store.domain.can_view(msg["channel_id"],_uid(connection),_admins(connection)): _error(connection,msg["id"],"channel_access"); return
    try: result=store.domain.key_state(_uid(connection),msg["channel_id"],_admins(connection))
    except PermissionError as err: _error(connection,msg["id"],str(err)); return
    result["security_code"]=store.domain.security_code(msg["channel_id"]) if store.settings()["show_security_details"] else None; _result(connection,msg["id"],result)

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/key/states"})
@websocket_api.async_response
async def _key_states(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    uid, admins = _uid(connection), _admins(connection)
    channels=store.domain.channels_for(uid,admins,store.settings()["enabled"],store.data["users"].get("allowed"))
    states=[]
    for channel in channels:
        try: state=store.domain.key_state(uid,channel["id"],admins)
        except PermissionError: continue
        state["security_code"]=store.domain.security_code(channel["id"]) if store.settings()["show_security_details"] else None
        states.append({"channel_id":channel["id"],**state})
    _result(connection,msg["id"],{"states":states})

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/key/devices", vol.Required("channel_id"): str})
@websocket_api.async_response
async def _key_devices(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    try: result=store.domain.devices_for_channel(_uid(connection),msg["channel_id"],_admins(connection))
    except PermissionError as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"],[{"id":d["id"],"user_id":d["user_id"],"public_key":d["public_key"]} for d in result])

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/key/request", vol.Required("channel_id"): str, vol.Required("device_id"): str})
@websocket_api.async_response
async def _key_request(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    try:
        store.check_rate(_uid(connection))
        if not store.domain.can_view(msg["channel_id"],_uid(connection),_admins(connection)) or msg["device_id"] not in store.data["devices"].get(_uid(connection),{}): raise PermissionError("device_access")
        result=store.domain.request_key(_uid(connection),msg["channel_id"],msg["device_id"]); await store.changed("key_request",channel_id=msg["channel_id"],request={key:value for key,value in result.items() if key != "user_id"})
    except (PermissionError,KeyError,ValueError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"],{"state":"waiting_for_device","request_id":result["id"]})

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/key/reset", vol.Required("channel_id"): str, vol.Required("device_id"): str, vol.Required("expected_epoch"): int})
@websocket_api.async_response
async def _key_reset(hass, connection, msg):
    store=_store(hass); channel=store.data["channels"].get(msg["channel_id"],{})
    if not _require_access(store,connection,msg["id"]): return
    try:
        store.check_rate(_uid(connection)); epoch=store.domain.reset_channel_key(_uid(connection),msg["channel_id"],msg["device_id"],msg["expected_epoch"],_admins(connection))
        await store.changed("key_reset",channel_id=msg["channel_id"],key_epoch=epoch,user_ids=list(channel.get("members",[])),**{"global":not channel.get("restricted",True)})
    except (PermissionError,ValueError,KeyError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"],{"key_epoch":epoch})

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/recovery/get"})
@websocket_api.async_response
async def _recovery_get(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    _result(connection,msg["id"],store.domain.get_recovery_bundle(_uid(connection)))

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/recovery/set", vol.Required("bundle"): dict})
@websocket_api.async_response
async def _recovery_set(hass, connection, msg):
    store=_store(hass)
    if not _require_access(store,connection,msg["id"]): return
    try:
        store.check_rate(_uid(connection)); result=store.domain.set_recovery_bundle(_uid(connection),msg["bundle"]); await store.async_save()
    except (PermissionError,ValueError) as err: _error(connection,msg["id"],str(err))
    else: _result(connection,msg["id"],result)

@websocket_api.websocket_command({vol.Required("type"): "home_assistant_chat/settings", vol.Optional("enabled"): bool, vol.Optional("allow_users"): bool, vol.Optional("allowed_users"): [str], vol.Optional("retention_days"): int, vol.Optional("show_security_details"): bool, vol.Optional("show_deleted_messages"): bool, vol.Optional("federation_qr_enabled"): bool, vol.Optional("federation_address"): str, vol.Optional("federation_port"): int})
@websocket_api.require_admin
@websocket_api.async_response
async def _settings(hass, connection, msg):
    store=_store(hass); updates={k:v for k,v in msg.items() if k in {"enabled","allow_users","retention_days","show_security_details","show_deleted_messages","federation_qr_enabled","federation_address","federation_port"}}
    proposed={**store.settings(), **updates}
    retention=proposed.get("retention_days")
    if isinstance(retention,bool) or not isinstance(retention,int) or not 0 <= retention <= 3650:
        _error(connection,msg["id"],"invalid_retention_days"); return
    allowed_update = None
    if "allowed_users" in msg:
        known={user.id for user in await hass.auth.async_get_users()}
        requested=msg["allowed_users"]
        if not isinstance(requested,list) or any(not isinstance(user_id,str) or user_id not in known for user_id in requested):
            _error(connection,msg["id"],"invalid_allowed_users"); return
        allowed_update=sorted(set(requested)) or None
    if proposed.get("federation_qr_enabled"):
        try:
            address, port = normalize_federation_endpoint(proposed.get("federation_address"), proposed.get("federation_port"))
        except ValueError as err:
            _error(connection,msg["id"],str(err)); return
        updates["federation_address"], updates["federation_port"] = address, port
    if "allowed_users" in msg: store.data["users"]["allowed"] = allowed_update
    if msg.get("show_deleted_messages") is False:
        for message_id in [message_id for message_id,message in store.data["messages"].items() if message.get("deleted")]: store.data["messages"].pop(message_id)
    hass.config_entries.async_update_entry(store.entry, options={**store.entry.options, **updates}); await store.changed("settings",**{"global":True}); _result(connection,msg["id"],store.settings())
