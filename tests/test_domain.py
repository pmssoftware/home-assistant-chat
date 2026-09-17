from pathlib import Path
import importlib.util
import sys
import types

ROOT=Path(__file__).parents[1]
pkg=types.ModuleType("custom_components.home_assistant_chat");pkg.__path__=[str(ROOT/"custom_components/home_assistant_chat")]
sys.modules.setdefault("custom_components",types.ModuleType("custom_components"));sys.modules["custom_components.home_assistant_chat"]=pkg
for name in ("const","domain"):
    spec=importlib.util.spec_from_file_location(f"custom_components.home_assistant_chat.{name}",ROOT/f"custom_components/home_assistant_chat/{name}.py")
    mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod)
ChatDomain=sys.modules["custom_components.home_assistant_chat.domain"].ChatDomain

def env(device="d",counter=1,key="public:1"):
    return {"version":"ha-chat/1","device_id":device,"counter":counter,"nonce":"AAAAAAAAAAAAAAAA","key_id":key,"aad":"cHVibGlj"}

def test_migration_adds_new_collections_and_defaults():
    d=ChatDomain({"schema_version":0,"server_id":"server_old","channels":{},"messages":{}})
    assert d.migrate()
    assert d.data["schema_version"] == 2
    assert {"blocks","mutes","devices","keys","seen","replay","users"} <= d.data.keys()

def test_replay_protection_and_key_epoch_rotation():
    d=ChatDomain.fresh();d.register_device("admin","d","pub")
    d.add_message("admin","public","Y2lwaGVy",env(),{"admin"})
    try:d.add_message("admin","public","Y2lwaGVy",env(),{"admin"})
    except ValueError as err:assert str(err)=="replayed_message"
    else:assert False
    before=d.data["channels"]["public"]["key_epoch"];d.set_members("admin",{"admin"},"public",{"admin","u"})
    assert d.data["channels"]["public"]["key_epoch"]==before+1

def test_mute_private_close_and_seen():
    d=ChatDomain.fresh();d.register_device("a","d","pub");d.set_mute("a","b",True,{"a"})
    try:d.add_message("b","public","Y2lwaGVy",env(),{"a"})
    except PermissionError:pass
    else:assert False
    r=d.resolve_private("a","Bob",[{"id":"b","name":"Bob","enabled":True}],{"b"},False)
    d.mark_seen("a",r["channel"]["id"],"message_x")
    try:d.delete_private("a",r["channel"]["id"],False)
    except PermissionError as err:assert str(err)=="confirm_delete"
    else:assert False
    d.delete_private("a",r["channel"]["id"],True)
    assert r["channel"]["id"] not in d.data["channels"]

def test_channel_lifecycle_access_and_device_revoke():
    d=ChatDomain.fresh(); channel=d.add_channel("admin",{"admin"},"Team","group",True,{"u"})
    assert channel["id"] in {c["id"] for c in d.channels_for("u",set(),True,None)}
    d.edit_channel("admin",{"admin"},channel["id"],"Renamed",True,{"u","v"})
    assert d.data["channels"][channel["id"]]["name"] == "Renamed"
    d.register_device("u","device-u","public-key")
    d.revoke_device("u","device-u",set())
    assert not d.data["devices"].get("u")
    try: d.delete_channel("admin",{"admin"},"public")
    except ValueError as err: assert str(err) == "default_channel"
    else: assert False

def test_announcements_are_visible_but_read_only_and_key_offers_use_visibility():
    d=ChatDomain.fresh(); d.register_device("u","du","pub-u")
    assert "announcements" in {c["id"] for c in d.channels_for("u",set(),True,None)}
    try:d.add_message("u","announcements","Y2lwaGVy",env("du"),set())
    except PermissionError:pass
    else:assert False
    wrapped='{"sender_device_id":"du","sender_public":{},"nonce":"AA==","ciphertext":"AA=="}'
    d.offer_key("u","announcements","du","announcements:1",wrapped,set())
    assert d.data["keys"]["announcements"]["announcements:1"]["du"]["from_device_id"] == "du"

def test_restricted_announcements_and_same_user_devices_follow_visibility():
    d=ChatDomain.fresh(); d.register_device("u","device-one","pub-1"); d.register_device("u","device-two","pub-2")
    channel=d.add_channel("admin",{"admin"},"Team news","announcement",True,{"u"})
    assert channel["id"] in {item["id"] for item in d.channels_for("u",set(),True,None)}
    assert {item["id"] for item in d.devices_for_channel("u",channel["id"])} == {"device-one","device-two"}
    assert channel["id"] not in {item["id"] for item in d.channels_for("other",set(),True,None)}
