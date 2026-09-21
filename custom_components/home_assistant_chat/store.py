from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Any, Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.storage import Store

from .const import DOMAIN, RATE_LIMIT_PER_MINUTE, STORAGE_KEY, STORAGE_VERSION
from .domain import ChatDomain, normalize_federation_endpoint

class ChatStore:
    """Persistent adapter around the transport-independent ChatDomain."""
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass, self.entry = hass, entry
        self._store = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        self.domain = ChatDomain.fresh()
        self._listeners: set[Callable[[dict[str, Any]], None]] = set()
        self._rate: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()
        self._last_cleanup = 0.0

    @property
    def data(self): return self.domain.data

    async def async_load(self) -> None:
        saved = await self._store.async_load()
        if saved: self.domain = ChatDomain(saved); self.domain.migrate()
        self.data["channels"].setdefault("public", {"id":"public","kind":"public","name":"Public chat","restricted":False,"members":[],"key_epoch":1})
        self.data["channels"].setdefault("announcements", {"id":"announcements","kind":"announcement","name":"Announcements","restricted":False,"members":[],"key_epoch":1})
        self.data["channels"]["announcements"]["restricted"] = False
        for channel in self.data["channels"].values(): channel.setdefault("key_epoch", 1)
        await self._cleanup_retention(force=True); await self._store.async_save(self.data)

    async def _cleanup_retention(self, force: bool = False) -> bool:
        now = time.time()
        if not force and now - self._last_cleanup < 60: return False
        self._last_cleanup = now
        changed = False
        try: days = int(self.entry.options.get("retention_days", self.entry.data.get("retention_days", 0)))
        except (TypeError, ValueError): days = 0
        if days > 0:
            cutoff = now - days * 86400
            for mid in [mid for mid,msg in self.data["messages"].items() if msg.get("created",0) < cutoff]:
                self.data["messages"].pop(mid, None); changed = True
        messages = self.data["messages"]
        if len(messages) > 50000:
            oldest = sorted(messages.items(), key=lambda item: (item[1].get("created", 0), item[0]))[:len(messages)-50000]
            for mid, _ in oldest: messages.pop(mid, None)
            changed = True
        cutoff = now - 86400
        for request_id, request in list(self.data.get("key_requests", {}).items()):
            try: created = float(request.get("created", 0))
            except (TypeError, ValueError): created = 0
            if created < cutoff:
                self.data["key_requests"].pop(request_id, None); changed = True
        live_ids = set(messages)
        for seen in self.data.get("seen", {}).values():
            if isinstance(seen, dict):
                for channel_id, message_id in list(seen.items()):
                    if message_id not in live_ids:
                        seen.pop(channel_id, None); changed = True
        return changed

    async def async_register(self) -> None:
        from .websocket import async_register_websocket
        async_register_websocket(self.hass, self)
    async def async_unregister(self) -> None: self._listeners.clear()

    @callback
    def subscribe(self, listener):
        self._listeners.add(listener); return lambda: self._listeners.discard(listener)

    async def changed(self, event: str, **payload) -> None:
        await self._cleanup_retention()
        for listener in tuple(self._listeners): listener({"event":event, **payload})
        await self.async_save()

    async def async_save(self) -> None:
        async with self._lock:
            await self._store.async_save(self.data)

    def settings(self) -> dict[str, Any]:
        return {key:self.entry.options.get(key, self.entry.data.get(key, default)) for key,default in {"enabled":True,"allow_users":True,"retention_days":0,"show_security_details":False,"show_deleted_messages":True,"federation_qr_enabled":False,"federation_address":"","federation_port":0}.items()}

    def identity_address(self, user_id: str) -> str:
        """Return a QR-safe local identity, optionally with the configured suffix."""
        number = str(self.domain.ensure_identity(user_id))
        settings = self.settings()
        if not settings["federation_qr_enabled"]:
            return number
        try:
            address, port = normalize_federation_endpoint(settings["federation_address"], settings["federation_port"])
        except ValueError:
            # Invalid legacy options must never make state loading fail or emit
            # an unsafe address. The settings command rejects new invalid data.
            return number
        return f"{number}@{address}:{port}"
    def can_use(self, user_id: str, is_admin: bool = False) -> bool:
        allowed=self.data.get("users",{}).get("allowed")
        return self.settings()["enabled"] and (is_admin or (self.settings()["allow_users"] and (allowed is None or user_id in allowed)))
    def check_rate(self, user_id: str) -> None:
        q=self._rate[user_id]; now=time.time()
        while q and now-q[0] > 60: q.popleft()
        if len(q) >= RATE_LIMIT_PER_MINUTE: raise ValueError("rate_limited")
        q.append(now)
