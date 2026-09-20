from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .panel import async_register_panel, async_unregister_panel
from .store import ChatStore

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    hass.data.setdefault(DOMAIN, {})
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    store = ChatStore(hass, entry)
    await store.async_load()
    hass.data[DOMAIN][entry.entry_id] = store
    await store.async_register()
    await async_register_panel(hass, entry.entry_id)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    store = hass.data[DOMAIN].pop(entry.entry_id)
    await store.async_unregister()
    if not hass.data[DOMAIN]:
        async_unregister_panel(hass)
    return True
