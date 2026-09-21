from pathlib import Path
import importlib.util
import sys
import types
import json

ROOT = Path(__file__).parents[1]
pkg = types.ModuleType("custom_components.home_assistant_chat")
pkg.__path__ = [str(ROOT / "custom_components/home_assistant_chat")]
sys.modules.setdefault("custom_components", types.ModuleType("custom_components"))
sys.modules["custom_components.home_assistant_chat"] = pkg
for name in ("const", "domain"):
    spec = importlib.util.spec_from_file_location(f"custom_components.home_assistant_chat.{name}", ROOT / f"custom_components/home_assistant_chat/{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
ChatDomain = sys.modules["custom_components.home_assistant_chat.domain"].ChatDomain
validate_envelope = sys.modules["custom_components.home_assistant_chat.domain"].validate_envelope

DEVICE_ID = "00000000-0000-4000-8000-000000000001"
PUBLIC_JWK = json.dumps({"kty": "EC", "crv": "P-256", "x": "_EFaiOShryGXKUj1-JxABWtIOpjR2D7cWDyNx0hnJMI", "y": "n-B-Q7GXGPjWGAzfLV2oyEUpZksgBILRinwXcwlgDKY", "ext": True, "key_ops": []}, separators=(",", ":"))

def envelope(channel="public"):
    import base64
    return {"version":"ha-chat/1","device_id":DEVICE_ID,"counter":1,"nonce":"AAAAAAAAAAAAAAAA","key_id":f"{channel}:1","aad":base64.b64encode(channel.encode()).decode()}

def test_exact_handle_privacy_and_invalid_is_empty():
    d=ChatDomain.fresh()
    assert d.resolve_private("a","Alex",[{"id":"b","name":"Alex","enabled":True}],{"b"},False)["user"]["name"] == "Alex"
    try: d.resolve_private("a","missing",[{"id":"b","name":"Alex","enabled":True}],{"b"},False)
    except ValueError as err: assert str(err) == "invalid_handle"
    else: assert False

def test_block_and_one_sided_unblock():
    d=ChatDomain.fresh(); d.add_block("a","b")
    try: d.resolve_private("a","Bob",[{"id":"b","name":"Bob","enabled":True}],{"b"},False)
    except PermissionError as err: assert str(err) == "confirm_unblock"
    else: assert False
    assert d.resolve_private("a","Bob",[{"id":"b","name":"Bob","enabled":True}],{"b"},True)["unblocked"]
    d.add_block("b","a")
    try: d.resolve_private("a","Bob",[{"id":"b","name":"Bob","enabled":True}],{"b"},True)
    except PermissionError as err: assert str(err) == "blocked_by_other"
    else: assert False

def test_delete_announcements_and_envelope():
    d=ChatDomain.fresh(); admins={"admin"}; d.register_device("admin",DEVICE_ID,PUBLIC_JWK)
    try: d.add_message("user","announcements","AAAAAAAAAAAAAAAAAAAAAA==",envelope("announcements"),admins)
    except PermissionError: pass
    else: assert False
    msg=d.add_message("admin","announcements","AAAAAAAAAAAAAAAAAAAAAA==",envelope("announcements"),admins)
    d.delete_message("admin",msg["id"],admins)
    assert d.data["messages"][msg["id"]]["ciphertext"] == ""
    validate_envelope("AAAAAAAAAAAAAAAAAAAAAA==",envelope())

def test_users_delete_only_their_own_messages_and_can_purge_without_marker():
    d=ChatDomain.fresh(); d.register_device("user",DEVICE_ID,PUBLIC_JWK)
    msg=d.add_message("user","public","AAAAAAAAAAAAAAAAAAAAAA==",envelope(),{"admin"})
    try: d.delete_message("admin",msg["id"],{"admin"})
    except PermissionError as err: assert str(err) == "message_access"
    else: assert False
    d.delete_message("user",msg["id"],{"admin"},keep_marker=False)
    assert msg["id"] not in d.data["messages"]

def test_non_admin_mutation_handlers_require_access_guard():
    source=(ROOT / "custom_components/home_assistant_chat/websocket.py").read_text()
    for handler in ("_message_delete", "_private_delete", "_private_silence", "_unblock", "_seen"):
        start=source.index(f"async def {handler}")
        end=source.find("\n@websocket_api.websocket_command", start)
        assert "_require_access(store,connection,msg[\"id\"])" in source[start:end]

def test_batched_key_states_endpoint_is_registered_and_guarded():
    source=(ROOT / "custom_components/home_assistant_chat/websocket.py").read_text()
    assert "_key_states" in source and 'home_assistant_chat/key/states' in source
    start=source.index("async def _key_states")
    end=source.find("\n@websocket_api.websocket_command", start)
    assert "_require_access(store,connection,msg[\"id\"])" in source[start:end]

def test_admin_access_bypasses_regular_user_allowlist_but_not_global_disable():
    source=(ROOT / "custom_components/home_assistant_chat/store.py").read_text()
    assert "def can_use(self, user_id: str, is_admin: bool = False)" in source
    assert "self.settings()[\"enabled\"] and (is_admin or" in source
    domain=ChatDomain.fresh(); domain.data["users"]["allowed"]=[]
    assert domain.can_access("admin",True, set(), {"admin"})
    assert not domain.can_access("admin",False, set(), {"admin"})

def test_history_is_bounded_and_subscriptions_recheck_access():
    source=(ROOT / "custom_components/home_assistant_chat/websocket.py").read_text()
    assert "home_assistant_chat/history" in source
    assert "MESSAGE_PAGE_SIZE = 100" in source
    assert "if not store.can_use(uid,is_admin): return" in source
    assert 'request={key:value for key,value in result.items() if key != "user_id"}' in source
