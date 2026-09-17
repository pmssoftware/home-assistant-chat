from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Any, Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.storage import Store

from .const import DOMAIN, RATE_LIMIT_PER_MINUTE, STORAGE_KEY, STORAGE_VERSION
from .domain import ChatDomain

class ChatStore:
    """Persistent adapter around the transport-independent ChatDomain."""
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass, self.entry = hass, entry
        self._store = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        self.domain = ChatDomain.fresh()
        self._listeners: set[Callable[[dict[str, Any]], None]] = set()
        self._rate: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    @property
    def data(self): return self.domain.data

    async def async_load(self) -> None:
        saved = await self._store.async_load()
        if saved: self.domain = ChatDomain(saved); self.domain.migrate()
        self.data["channels"].setdefault("public", {"id":"public","kind":"public","name":"Public chat","restricted":False,"members":[],"key_epoch":1})
        self.data["channels"].setdefault("announcements", {"id":"announcements","kind":"announcement","name":"Announcements","restricted":True,"members":[],"key_epoch":1})
        for channel in self.data["channels"].values(): channel.setdefault("key_epoch", 1)
        await self._cleanup_retention(); await self._store.async_save(self.data)

    async def _cleanup_retention(self) -> None:
        days = int(self.entry.options.get("retention_days", self.entry.data.get("retention_days", 0)))
        if days <= 0: return
        cutoff = time.time() - days * 86400
        for mid in [mid for mid,msg in self.data["messages"].items() if msg.get("created",0) < cutoff]: self.data["messages"].pop(mid, None)

    async def async_register(self) -> None:
        from .websocket import async_register_websocket
        async_register_websocket(self.hass, self)
    async def async_unregister(self) -> None: self._listeners.clear()

    @callback
    def subscribe(self, listener):
        self._listeners.add(listener); return lambda: self._listeners.discard(listener)

    async def changed(self, event: str, **payload) -> None:
        for listener in tuple(self._listeners): listener({"event":event, **payload})
        await self._store.async_save(self.data)

    def settings(self) -> dict[str, Any]:
        return {key:self.entry.options.get(key, self.entry.data.get(key, default)) for key,default in {"enabled":True,"allow_users":True,"retention_days":0,"encryption_enabled":True,"show_security_details":False}.items()}
    def can_use(self, user_id: str) -> bool:
        allowed=self.data.get("users",{}).get("allowed")
        return self.settings()["enabled"] and self.settings()["allow_users"] and (allowed is None or user_id in allowed)
    def check_rate(self, user_id: str) -> None:
        q=self._rate[user_id]; now=time.time()
        while q and now-q[0] > 60: q.popleft()
        if len(q) >= RATE_LIMIT_PER_MINUTE: raise ValueError("rate_limited")
        q.append(now)
