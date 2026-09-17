from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries

from .const import DOMAIN

class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="Home Assistant Chat", data=user_input)
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required("enabled", default=True): bool,
                vol.Required("allow_users", default=True): bool,
                vol.Optional("retention_days", default=0): vol.All(int, vol.Range(min=0, max=3650)),
                vol.Required("encryption_enabled", default=True): bool,
                vol.Required("show_security_details", default=False): bool,
            }),
        )
