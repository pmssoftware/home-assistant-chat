"""Pure authorization rules, kept independent from Home Assistant transport."""
def private_lookup(users: list[dict], handle: str, enabled: set[str]) -> list[dict]:
    matches = [u for u in users if u.get("enabled") and u.get("id") in enabled and u.get("name") == handle]
    return [{"id": u["id"], "name": u["name"]} for u in matches]

def blocked(blocks: dict[str, set[str]], a: str, b: str) -> bool:
    return b in blocks.get(a, set()) or a in blocks.get(b, set())

def unblock_for_new_chat(blocks: dict[str, set[str]], starter: str, target: str) -> bool:
    if target in blocks.get(starter, set()):
        blocks[starter].discard(target)
        return True
    return False

def can_delete_message(message: dict, actor: str, admin: bool) -> bool:
    return admin or message.get("sender_id") == actor

def can_post(channel: dict, actor: str, admin: bool, members: set[str]) -> bool:
    if channel.get("kind") == "announcement": return admin
    if channel.get("restricted"): return admin or actor in members
    return True
