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
normalize_federation_endpoint=sys.modules["custom_components.home_assistant_chat.domain"].normalize_federation_endpoint

def env(device="d",counter=1,key="public:1"):
    return {"version":"ha-chat/1","device_id":device,"counter":counter,"nonce":"AAAAAAAAAAAAAAAA","key_id":key,"aad":"cHVibGlj"}

def test_migration_adds_new_collections_and_defaults():
    d=ChatDomain({"schema_version":0,"server_id":"server_old","channels":{},"messages":{}})
    assert d.migrate()
    assert d.data["schema_version"] == 4
    assert {"blocks","mutes","devices","keys","seen","replay","users"} <= d.data.keys()

def test_migration_repairs_identity_reverse_index():
    d=ChatDomain({"schema_version":2,"server_id":"s","identities":{"alice":12345678},"identity_users":{"12345678":"wrong","99999999":"stale"}})
    assert d.migrate(); assert d.data["identity_users"] == {"12345678":"alice"}
    assert d.ensure_identity("alice") == 12345678

def test_malformed_or_deleted_private_data_does_not_break_visible_channels():
    d=ChatDomain.fresh(); d.data["identities"]={"alice":"not-a-number","deleted":12345678}; d.data["identity_users"]={"12345678":"deleted"}
    assert 10000000 <= d.ensure_identity("alice") <= 99999999
    d.data["channels"]["stale"]={"id":"stale","kind":"private","members":["alice"]}
    assert all(channel["id"] != "stale" for channel in d.channels_for("alice",set(),True,None))

def test_recovery_bundle_is_opaque_isolated_validated_and_migrated():
    d=ChatDomain({"schema_version":3,"server_id":"s","recovery":{"alice":{"version":1,"ciphertext":"YQ==","salt":"Yg==","nonce":"Yw==","kdf":{},"updated":1}}})
    assert d.migrate() and d.get_recovery_bundle("alice")["ciphertext"] == "YQ=="
    assert d.get_recovery_bundle("bob") is None
    import base64
    bundle={"version":1,"ciphertext":base64.b64encode(b"ciphertext-value").decode(),"salt":base64.b64encode(b"0123456789abcdef").decode(),"nonce":base64.b64encode(b"0123456789ab").decode(),"kdf":{"name":"PBKDF2","hash":"SHA-256","iterations":200000}}
    stored=d.set_recovery_bundle("bob",bundle)
    assert stored["updated"] > 0 and d.get_recovery_bundle("alice")["ciphertext"] == "YQ=="
    try:d.set_recovery_bundle("bob",{"version":1,"ciphertext":"not-base64","salt":"Yg==","nonce":"Yw==","kdf":{}})
    except ValueError as err: assert str(err) == "invalid_recovery_bundle"
    else: assert False
    bad=dict(bundle); bad["kdf"]={"name":"PBKDF2","hash":"SHA-256","iterations":True}
    try:d.set_recovery_bundle("bob",bad)
    except ValueError as err: assert str(err) == "invalid_recovery_bundle"
    else: assert False

def test_numeric_identities_are_stable_unique_and_parse_federated_syntax():
    d=ChatDomain.fresh("server"); first=d.ensure_identity("alice"); assert d.ensure_identity("alice")==first
    second=d.ensure_identity("bob"); assert second != first and d.data["identity_users"][str(first)] == "alice"
    assert d.parse_identity(str(first)) == (first,None)
    try:d.parse_identity(f"{first}@remote.example:8123")
    except ValueError as err: assert str(err) == "federated_identity_not_supported"
    else: assert False

def test_federation_qr_endpoint_is_strictly_normalized():
    assert normalize_federation_endpoint("Example.org", 8123) == ("example.org", 8123)
    assert normalize_federation_endpoint("192.168.69.250", 8123) == ("192.168.69.250", 8123)
    for address, port in (("https://example.org", 443), ("example.org/path", 443), ("example.org", 0), ("example.org", 65536), ("example.org", True), ("2001:db8::1", 443), ("[2001:db8::1]", 443)):
        try: normalize_federation_endpoint(address, port)
        except ValueError: pass
        else: assert False

def test_private_chat_resolves_numeric_identity_and_preserves_name_lookup():
    d=ChatDomain.fresh(); d.ensure_identity("alice"); number=d.ensure_identity("bob")
    users=[{"id":"alice","name":"Alice","enabled":True},{"id":"bob","name":"Bob","enabled":True}]
    result=d.resolve_private("alice",str(number),users,{"alice","bob"},False)
    assert result["channel"]["members"] == ["alice","bob"]
    assert d.resolve_private("alice","Bob",users,{"alice","bob"},False)["channel"]["id"] == result["channel"]["id"]

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

def test_private_chat_silence_is_personal_and_removed_with_chat():
    d=ChatDomain.fresh()
    result=d.resolve_private("a","Bob",[{"id":"b","name":"Bob","enabled":True}],{"b"},False)
    channel_id=result["channel"]["id"]
    d.set_private_silenced("a",channel_id,True)
    assert d.data["silenced"]["a"] == [channel_id]
    assert not d.data["silenced"].get("b")
    try:d.set_private_silenced("other",channel_id,True)
    except PermissionError as err:assert str(err)=="channel_access"
    else:assert False
    d.delete_private("a",channel_id,True)
    assert d.data["silenced"]["a"] == []

def test_visible_user_can_rotate_key_without_deleting_old_messages():
    d=ChatDomain.fresh(); d.register_device("a","device-a","public-key")
    message=d.add_message("a","public","Y2lwaGVy",env("device-a"),set())
    d.request_key("a","public","device-a")
    assert d.reset_channel_key("a","public","device-a",1,set()) == 2
    assert d.data["messages"][message["id"]] == message

def test_group_key_reset_rejects_stale_concurrent_attempts():
    d=ChatDomain.fresh(); channel=d.add_channel("admin",{"admin"},"Group","group",True,{"a","b"})
    d.register_device("a","device-a","pub-a"); d.register_device("b","device-b","pub-b")
    d.request_key("a",channel["id"],"device-a"); d.request_key("b",channel["id"],"device-b")
    assert d.reset_channel_key("a",channel["id"],"device-a",1,set()) == 2
    try:d.reset_channel_key("b",channel["id"],"device-b",1,set())
    except ValueError as err:assert str(err)=="stale_key_epoch"
    else:assert False
    assert d.data["channels"][channel["id"]]["members"] == ["a","b"]
