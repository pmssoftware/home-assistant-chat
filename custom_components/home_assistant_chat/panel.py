from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote
from homeassistant.components import frontend, panel_custom
from homeassistant.components.http import StaticPathConfig
from homeassistant.core import HomeAssistant

from .const import DOMAIN, PANEL_TITLE, PANEL_URL

PANEL_NAME = "ha-home-assistant-chat-panel"
STATIC_PATH = f"/api/{DOMAIN}/static"

def _frontend_version() -> str:
    manifest = Path(__file__).parent / "manifest.json"
    return str(json.loads(manifest.read_text(encoding="utf-8"))["version"])

async def async_register_panel(hass: HomeAssistant, entry_id: str) -> None:
    www = Path(__file__).parent / "frontend"
    if not frontend.async_panel_exists(hass, PANEL_URL):
        await hass.http.async_register_static_paths([StaticPathConfig(STATIC_PATH, str(www), False)])
        await panel_custom.async_register_panel(
            hass, webcomponent_name=PANEL_NAME, frontend_url_path=PANEL_URL,
            module_url=f"{STATIC_PATH}/panel.js?v={quote(_frontend_version(), safe='')}", sidebar_title=PANEL_TITLE,
            sidebar_icon="mdi:chat-processing", require_admin=False,
            config={"entry_id": entry_id}, config_panel_domain=DOMAIN,
        )

def async_unregister_panel(hass: HomeAssistant) -> None:
    frontend.async_remove_panel(hass, PANEL_URL)
