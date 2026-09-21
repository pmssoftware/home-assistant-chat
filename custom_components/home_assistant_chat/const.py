from __future__ import annotations

from dataclasses import dataclass

DOMAIN = "home_assistant_chat"
PANEL_URL = "home-assistant-chat"
PANEL_TITLE = "Chat"
STORAGE_VERSION = 2
STORAGE_KEY = f"{DOMAIN}.storage"
PROTOCOL_VERSION = "ha-chat/1"
MAX_MESSAGE_LENGTH = 4000
RATE_LIMIT_PER_MINUTE = 30

@dataclass(frozen=True, slots=True)
class ChatConfig:
    enabled: bool = True
    allow_users: bool = True
    retention_days: int = 0
    show_security_details: bool = False
    show_deleted_messages: bool = True
