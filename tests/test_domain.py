from pathlib import Path
import importlib.util
import sys
import types
import json

ROOT=Path(__file__).parents[1]
pkg=types.ModuleType("custom_components.home_assistant_chat");pkg.__path__=[str(ROOT/"custom_components/home_assistant_chat")]
sys.modules.setdefault("custom_components",types.ModuleType("custom_components"));sys.modules["custom_components.home_assistant_chat"]=pkg
for name in ("const","domain"):
    spec=importlib.util.spec_from_file_location(f"custom_components.home_assistant_chat.{name}",ROOT/f"custom_components/home_assistant_chat/{name}.py")
    mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod)
ChatDomain=sys.modules["custom_components.home_assistant_chat.domain"].ChatDomain
validate_envelope=sys.modules["custom_components.home_assistant_chat.domain"].validate_envelope
normalize_federation_endpoint=sys.modules["custom_components.home_assistant_chat.domain"].normalize_federation_endpoint

DEVICE_IDS = {
    "a": "00000000-0000-4000-8000-000000000001",
    "b": "00000000-0000-4000-8000-000000000002",
    "u": "00000000-0000-4000-8000-000000000003",
    "one": "00000000-0000-4000-8000-000000000004",
    "two": "00000000-0000-4000-8000-000000000005",
}
PUBLIC_JWK = json.dumps({"kty": "EC", "crv": "P-256", "x": "_EFaiOShryGXKUj1-JxABWtIOpjR2D7cWDyNx0hnJMI", "y": "n-B-Q7GXGPjWGAzfLV2oyEUpZksgBILRinwXcwlgDKY", "ext": True, "key_ops": []}, separators=(",", ":"))

def device(label):
    return DEVICE_IDS[label]

def wrapped(sender):
    return json.dumps({"nonce": "AAAAAAAAAAAAAAAA", "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA==", "sender_public": json.loads(PUBLIC_JWK), "sender_device_id": sender}, separators=(",", ":"))

def env(device_id=None,counter=1,key="public:1"):
    device_id = device_id or device("a")
    return {"version":"ha-chat/1","device_id":device_id,"counter":counter,"nonce":"AAAAAAAAAAAAAAAA","key_id":key,"aad":"cHVibGlj"}

def test_migration_adds_new_collections_and_defaults():
    d=ChatDomain({"schema_version":0,"server_id":"server_old","channels":{},"messages":{}})
    assert d.migrate()
    assert d.data["schema_version"] == 5
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

def test_key_requests_deduplicate_and_are_cleared_by_target_offer():
    d=ChatDomain.fresh(); d.register_device("admin",device("a"),PUBLIC_JWK); d.register_device("admin",device("b"),PUBLIC_JWK)
    first=d.request_key("admin","public",device("a")); assert d.request_key("admin","public",device("a"))["id"] == first["id"]
    d.offer_key("admin","public",device("a"),"public:1",wrapped(device("b")),set())
    assert not d.data["key_requests"]

def test_key_offers_keep_multiple_senders_and_reject_conflicting_retry():
    d=ChatDomain.fresh(); d.register_device("admin",device("a"),PUBLIC_JWK); d.register_device("admin",device("b"),PUBLIC_JWK)
    first=wrapped(device("a")); second=wrapped(device("b"))
    d.offer_key("admin","public",device("a"),"public:1",first,set())
    d.offer_key("admin","public",device("a"),"public:1",second,set())
    d.offer_key("admin","public",device("a"),"public:1",first,set())
    assert set(d.data["keys"]["public"]["public:1"][device("a")]) == {device("a"), device("b")}
    try: d.offer_key("admin","public",device("a"),"public:1",first.replace("AAAAAAAAAAAAAAAA", "AQEBAQEBAQEBAQEB"),set())
    except ValueError as err: assert str(err) == "key_offer_conflict"
    else: assert False
    state=d.key_state("admin","public",set())
    assert state["state"] == "ready" and len(state["offers"]) == 2

def test_migrate_legacy_key_offer_shape_without_cross_account_leakage():
    legacy=wrapped(device("a"))
    d=ChatDomain.fresh(); d.data["keys"]={"public":{"public:1":{device("b"):{"device_id":device("b"),"wrapped_key":legacy,"from_device":"admin","from_device_id":device("a")},device("a"):{"malformed":True}}}}
    assert d.migrate()
    assert list(d.data["keys"]["public"]["public:1"][device("b")]) == [device("a")]
    assert device("a") not in d.data["keys"]["public"]["public:1"]

def test_channel_deletion_purges_crypto_seen_and_silence_metadata():
    d=ChatDomain.fresh(); channel=d.add_channel("admin",{"admin"},"Temporary","group",True,{"alice"})
    cid=channel["id"]
    d.data["keys"][cid]={"%s:1" % cid:{}}
    d.data["key_commitments"][cid]={"%s:1" % cid:"A"*43+"="}
    d.data["key_requests"]={"r":{"id":"r","channel_id":cid,"device_id":"x","user_id":"alice"}}
    d.data["seen"]={"alice":{cid:"m"}}; d.data["silenced"]={"alice":[cid]}
    d.delete_channel("admin",{"admin"},cid)
    assert cid not in d.data["keys"] and cid not in d.data["key_commitments"]
    assert not d.data["key_requests"] and cid not in d.data["seen"]["alice"] and not d.data["silenced"]["alice"]

def test_revoke_device_purges_nested_offers_requests_and_only_its_replay():
    d=ChatDomain.fresh(); d.register_device("admin",device("a"),PUBLIC_JWK); d.register_device("admin",device("b"),PUBLIC_JWK)
    d.data["keys"]={"public":{"public:1":{device("a"):{device("a"):{"device_id":device("a"),"from_device_id":device("a")},device("b"):{"device_id":device("a"),"from_device_id":device("b")}}}}}
    d.data["key_requests"]={"a":{"channel_id":"public","device_id":device("a")},"b":{"channel_id":"public","device_id":device("b")}}
    d.data["replay"]={device("a"):4,device("b"):8}
    d.revoke_device("admin",device("a"),{"admin"})
    assert not d.data["keys"]["public"]["public:1"] and "a" not in d.data["key_requests"] and device("a") not in d.data["replay"] and d.data["replay"][device("b")] == 8

def test_device_key_conflict_and_canonical_coordinate_validation():
    d=ChatDomain.fresh(); d.register_device("a",device("a"),PUBLIC_JWK)
    try: d.register_device("a",device("a"),PUBLIC_JWK.replace("_EFai", "AEFai"))
    except ValueError as err: assert str(err) == "device_key_conflict"
    else: assert False
    try: d.register_device("b",device("b"),PUBLIC_JWK.replace("_EFai", "!EFai"))
    except ValueError as err: assert str(err) == "invalid_device"
    else: assert False

def test_oversized_base64_and_per_user_key_request_limits_are_rejected_early():
    from custom_components.home_assistant_chat.domain import validate_envelope
    oversized="A" * 30000
    try: validate_envelope(oversized,{**env(),"aad":"cHVibGlj"})
    except ValueError as err: assert str(err) == "invalid_ciphertext"
    else: assert False

def test_key_offer_normalizes_malformed_json_sender_and_commitment_errors():
    d=ChatDomain.fresh(); d.register_device("a",device("a"),PUBLIC_JWK)
    for malformed, commitment in (("[]", ""), (wrapped(device("a")), True)):
        try: d.offer_key("a","public",device("a"),"public:1",malformed,set(),commitment)
        except ValueError as err: assert str(err) == "invalid_key_offer"
        else: assert False
    d.data["devices"]["a"][device("a")]["public_key"]="["
    try: d.offer_key("a","public",device("a"),"public:1",wrapped(device("a")),set(),"")
    except ValueError as err: assert str(err) == "invalid_key_offer"
    else: assert False
    d=ChatDomain.fresh()
    for index in range(64): d.request_key("a",f"channel-{index}",device("a"))
    try: d.request_key("a","channel-64",device("a"))
    except ValueError as err: assert str(err) == "key_request_limit"
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
    d=ChatDomain.fresh();d.register_device("admin",device("a"),PUBLIC_JWK)
    first=env(); first["key_commitment"]="A"*43+"="; d.add_message("admin","public","AAAAAAAAAAAAAAAAAAAAAA==",first,{"admin"})
    try:d.add_message("admin","public","AAAAAAAAAAAAAAAAAAAAAA==",{**env(counter=1),"key_commitment":"A"*43+"="},{"admin"})
    except ValueError as err:assert str(err)=="replayed_message"
    else:assert False
    before=d.data["channels"]["public"]["key_epoch"];d.set_members("admin",{"admin"},"public",{"admin","u"})
    assert d.data["channels"]["public"]["key_epoch"]==before+1

def test_first_channel_key_commitment_wins_and_is_exposed_in_key_state():
    d=ChatDomain.fresh(); d.register_device("alice",device("a"),PUBLIC_JWK); d.register_device("bob",device("b"),PUBLIC_JWK)
    first="A"*43+"="; second="B"*43+"="
    d.add_message("alice","public","AAAAAAAAAAAAAAAAAAAAAA==",{**env(device("a"),1),"key_commitment":first},{"alice"})
    state=d.key_state("bob","public",set())
    assert state["commitment"] == first and state["commitments"]["public:1"] == first
    try: d.add_message("bob","public","AAAAAAAAAAAAAAAAAAAAAA==",{**env(device("b"),1),"key_commitment":second},{"alice"})
    except ValueError as err: assert str(err) == "key_commitment_conflict"
    else: assert False

def test_mute_private_close_and_seen():
    d=ChatDomain.fresh();d.register_device("a",device("a"),PUBLIC_JWK);d.set_mute("a","b",True,{"a"})
    try:d.add_message("b","public","AAAAAAAAAAAAAAAAAAAAAA==",env(),{"a"})
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
    d.register_device("u",device("u"),PUBLIC_JWK)
    d.revoke_device("u",device("u"),set())
    assert not d.data["devices"].get("u")
    try: d.delete_channel("admin",{"admin"},"public")
    except ValueError as err: assert str(err) == "default_channel"
    else: assert False

def test_announcements_are_visible_but_read_only_and_key_offers_use_visibility():
    d=ChatDomain.fresh(); d.register_device("u",device("u"),PUBLIC_JWK)
    assert "announcements" in {c["id"] for c in d.channels_for("u",set(),True,None)}
    announcement_env=env(device("u")); announcement_env["key_id"]="announcements:1"
    try:d.add_message("u","announcements","AAAAAAAAAAAAAAAAAAAAAA==",announcement_env,set())
    except PermissionError:pass
    else:assert False
    d.offer_key("u","announcements",device("u"),"announcements:1",wrapped(device("u")),set())
    assert d.data["keys"]["announcements"]["announcements:1"][device("u")][device("u")]["from_device_id"] == device("u")

def test_restricted_announcements_and_same_user_devices_follow_visibility():
    d=ChatDomain.fresh(); d.register_device("u",device("one"),PUBLIC_JWK); d.register_device("u",device("two"),PUBLIC_JWK)
    channel=d.add_channel("admin",{"admin"},"Team news","announcement",True,{"u"})
    assert channel["id"] in {item["id"] for item in d.channels_for("u",set(),True,None)}
    assert {item["id"] for item in d.devices_for_channel("u",channel["id"])} == {device("one"),device("two")}
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

def test_deleted_private_chat_gets_a_fresh_id_when_recreated():
    d=ChatDomain.fresh()
    users=[{"id":"b","name":"Bob","enabled":True}]
    first=d.resolve_private("a","Bob",users,{"b"},False)["channel"]["id"]
    d.delete_private("a",first,True)
    second=d.resolve_private("a","Bob",users,{"b"},False)["channel"]["id"]
    assert second != first

def test_visible_user_can_rotate_key_without_deleting_old_messages():
    d=ChatDomain.fresh(); d.register_device("a",device("a"),PUBLIC_JWK)
    message=d.add_message("a","public","AAAAAAAAAAAAAAAAAAAAAA==",env(device("a")),set())
    d.request_key("a","public",device("a"))
    assert d.reset_channel_key("a","public",device("a"),1,set()) == 2
    assert d.data["messages"][message["id"]] == message

def test_group_key_reset_rejects_stale_concurrent_attempts():
    d=ChatDomain.fresh(); channel=d.add_channel("admin",{"admin"},"Group","group",True,{"a","b"})
    d.register_device("a",device("a"),PUBLIC_JWK); d.register_device("b",device("b"),PUBLIC_JWK)
    d.request_key("a",channel["id"],device("a")); d.request_key("b",channel["id"],device("b"))
    assert d.reset_channel_key("a",channel["id"],device("a"),1,set()) == 2
    try:d.reset_channel_key("b",channel["id"],device("b"),1,set())
    except ValueError as err:assert str(err)=="stale_key_epoch"
    else:assert False
    assert d.data["channels"][channel["id"]]["members"] == ["a","b"]

def test_message_envelope_rejects_extra_fields_bad_counters_and_wrong_aad():
    valid=env()
    for malformed in ({**valid,"unexpected":True},{**valid,"counter":True},{**valid,"counter":2**53}):
        try: validate_envelope("AAAAAAAAAAAAAAAAAAAAAA==",malformed)
        except ValueError: pass
        else: assert False
    d=ChatDomain.fresh(); d.register_device("admin",device("a"),PUBLIC_JWK)
    try: d.add_message("admin","public","AAAAAAAAAAAAAAAAAAAAAA==",{**valid,"aad":"YW5ub3VuY2VtZW50cw=="},{"admin"})
    except ValueError as err: assert str(err)=="invalid_aad"
    else: assert False

def test_message_envelope_rejects_unregistered_device_and_oversized_ciphertext():
    d=ChatDomain.fresh(); unregistered={**env(device("b"))}
    try: d.add_message("admin","public","AAAAAAAAAAAAAAAAAAAAAA==",unregistered,{"admin"})
    except ValueError as err: assert str(err)=="unknown_device"
    else: assert False
    d.register_device("admin",device("a"),PUBLIC_JWK)
    import base64
    oversized=base64.b64encode(b"x"*(4000*4+17)).decode()
    try: d.add_message("admin","public",oversized,env(),{"admin"})
    except ValueError as err: assert str(err)=="invalid_ciphertext"
    else: assert False

def test_key_request_global_limit_is_bounded():
    d=ChatDomain.fresh()
    d.data["key_requests"]={str(index):{"user_id":"u","channel_id":f"channel-{index}","device_id":device("a")} for index in range(256)}
    try: d.request_key("u","new-channel",device("a"))
    except ValueError as err: assert str(err)=="key_request_limit"
    else: assert False
