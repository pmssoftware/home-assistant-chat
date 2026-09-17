from pathlib import Path
import importlib.util
import sys
import types

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

def envelope():
    return {"version":"ha-chat/1","device_id":"device-a","counter":1,"nonce":"AAAAAAAAAAAAAAAA","key_id":"public:1","aad":"cHVibGlj"}

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
    d=ChatDomain.fresh(); admins={"admin"}; d.register_device("admin","device-a","public-key")
    try: d.add_message("user","announcements","Y2lwaGVy",envelope(),admins)
    except PermissionError: pass
    else: assert False
    msg=d.add_message("admin","announcements","Y2lwaGVy",envelope(),admins)
    d.delete_message("admin",msg["id"],admins)
    assert d.data["messages"][msg["id"]]["ciphertext"] == ""
    validate_envelope("Y2lwaGVy",envelope())
