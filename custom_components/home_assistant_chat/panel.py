from __future__ import annotations

from pathlib import Path
from homeassistant.components import frontend, panel_custom
from homeassistant.components.http import StaticPathConfig
from homeassistant.core import HomeAssistant

from .const import DOMAIN, PANEL_TITLE, PANEL_URL

PANEL_NAME = f"{DOMAIN}-panel"
STATIC_PATH = f"/api/{DOMAIN}/static"

async def async_register_panel(hass: HomeAssistant, entry_id: str) -> None:
    www = Path(__file__).parent / "frontend"
    if not frontend.async_panel_exists(hass, PANEL_URL):
        await hass.http.async_register_static_paths([StaticPathConfig(STATIC_PATH, str(www), False)])
        await panel_custom.async_register_panel(
            hass, webcomponent_name=PANEL_NAME, frontend_url_path=PANEL_URL,
            module_url=f"{STATIC_PATH}/panel.js", sidebar_title=PANEL_TITLE,
            sidebar_icon="mdi:chat-processing", require_admin=False,
            config={"entry_id": entry_id}, config_panel_domain=DOMAIN,
        )

def async_unregister_panel(hass: HomeAssistant) -> None:
    frontend.async_remove_panel(hass, PANEL_URL)
