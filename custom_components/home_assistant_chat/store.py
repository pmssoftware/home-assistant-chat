from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections import defaultdict, deque
from typing import Any, Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.storage import Store

from .const import ATTACHMENT_CHUNK_SIZE, DOMAIN, MAX_ACTIVE_ATTACHMENTS_PER_USER, MAX_ATTACHMENT_SIZE, MAX_ATTACHMENT_STORAGE, MAX_PENDING_ATTACHMENT_BYTES_PER_USER, RATE_LIMIT_PER_MINUTE, STORAGE_KEY, STORAGE_VERSION
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
        self._media_path = hass.config.path(".storage", f"{DOMAIN}_media")
        self._uploads: dict[str, dict[str, Any]] = {}
        self._attachment_lock = asyncio.Lock()

    @property
    def data(self): return self.domain.data

    async def async_load(self) -> None:
        saved = await self._store.async_load()
        if saved: self.domain = ChatDomain(saved); self.domain.migrate()
        self.data.setdefault("attachments", {})
        await self.hass.async_add_executor_job(os.makedirs, self._media_path, 0o700, True)
        await self.hass.async_add_executor_job(self._remove_partial_uploads)
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
        await self.async_cleanup_attachments()
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
        await self.async_cleanup_attachments()
        for listener in tuple(self._listeners): listener({"event":event, **payload})
        await self.async_save()

    async def async_save(self) -> None:
        async with self._lock:
            await self._store.async_save(self.data)

    def settings(self) -> dict[str, Any]:
        return {key:self.entry.options.get(key, self.entry.data.get(key, default)) for key,default in {"enabled":True,"allow_users":True,"attachments_enabled":True,"retention_days":0,"show_security_details":False,"show_deleted_messages":True,"federation_qr_enabled":False,"federation_address":"","federation_port":0}.items()}

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

    def _attachment_path(self, attachment_id: str, partial: bool = False) -> str:
        return os.path.join(self._media_path, f"{attachment_id}{'.part' if partial else '.bin'}")

    def _remove_partial_uploads(self) -> None:
        if not os.path.isdir(self._media_path): return
        for name in os.listdir(self._media_path):
            if name.endswith(".part"):
                try: os.unlink(os.path.join(self._media_path,name))
                except OSError: pass

    async def begin_attachment(self, user_id: str, channel_id: str, attachment_id: str, size: int, admins: set[str]) -> None:
        if not self.settings()["attachments_enabled"]: raise PermissionError("attachments_disabled")
        try: parsed=uuid.UUID(attachment_id)
        except (ValueError,TypeError,AttributeError) as err: raise ValueError("invalid_attachment") from err
        if str(parsed)!=attachment_id or parsed.version!=4 or isinstance(size,bool) or not 17 <= size <= MAX_ATTACHMENT_SIZE + 16: raise ValueError("invalid_attachment")
        if not self.domain.can_post(channel_id,user_id,admins): raise PermissionError("channel_access")
        async with self._attachment_lock:
            active=[item for item in self._uploads.values() if item["owner"]==user_id]
            pending=[item for item in self.data["attachments"].values() if item.get("owner")==user_id and not item.get("message_id")]
            if len(active)>=MAX_ACTIVE_ATTACHMENTS_PER_USER or sum(int(item.get("size",0)) for item in active+pending)+size>MAX_PENDING_ATTACHMENT_BYTES_PER_USER: raise ValueError("attachment_quota")
            used=sum(int(item.get("size",0)) for item in self.data["attachments"].values()) + sum(int(item["size"]) for item in self._uploads.values())
            if used + size > MAX_ATTACHMENT_STORAGE: raise ValueError("attachment_storage_full")
            if attachment_id in self._uploads or attachment_id in self.data["attachments"]: raise ValueError("attachment_exists")
            self._uploads[attachment_id]={"owner":user_id,"channel_id":channel_id,"size":size,"received":0,"created":time.time()}
            path=self._attachment_path(attachment_id,True)
            try: await self.hass.async_add_executor_job(lambda: open(path,"xb").close())
            except Exception: self._uploads.pop(attachment_id,None); raise

    async def append_attachment(self, user_id: str, attachment_id: str, offset: int, chunk: bytes) -> int:
        if not self.settings()["attachments_enabled"]: raise PermissionError("attachments_disabled")
        async with self._attachment_lock:
            upload=self._uploads.get(attachment_id)
            if not upload or upload["owner"]!=user_id: raise PermissionError("attachment_access")
            if isinstance(offset,bool) or offset!=upload["received"] or not chunk or len(chunk)>ATTACHMENT_CHUNK_SIZE or offset+len(chunk)>upload["size"]: raise ValueError("invalid_attachment_chunk")
            path=self._attachment_path(attachment_id,True)
            def append():
                with open(path,"ab") as handle: handle.write(chunk)
            await self.hass.async_add_executor_job(append); upload["received"] += len(chunk); return upload["received"]

    async def finish_attachment(self, user_id: str, attachment_id: str) -> dict[str, Any]:
        if not self.settings()["attachments_enabled"]: raise PermissionError("attachments_disabled")
        async with self._attachment_lock:
            upload=self._uploads.get(attachment_id)
            if not upload or upload["owner"]!=user_id: raise PermissionError("attachment_access")
            if upload["received"]!=upload["size"]: raise ValueError("attachment_incomplete")
            await self.hass.async_add_executor_job(os.replace,self._attachment_path(attachment_id,True),self._attachment_path(attachment_id))
            record={**upload,"complete":True,"message_id":None}; record.pop("received",None); self.data["attachments"][attachment_id]=record; self._uploads.pop(attachment_id,None); await self.async_save(); return record

    def validate_attachment(self, user_id: str, channel_id: str, attachment_id: str) -> dict[str, Any]:
        if not self.settings()["attachments_enabled"]: raise PermissionError("attachments_disabled")
        record=self.data["attachments"].get(attachment_id)
        if not record or record.get("owner")!=user_id or record.get("channel_id")!=channel_id or record.get("message_id") is not None: raise ValueError("invalid_attachment")
        return record

    async def link_attachment(self, attachment_id: str, message_id: str) -> None:
        self.data["attachments"][attachment_id]["message_id"]=message_id

    async def discard_attachment(self, user_id: str, attachment_id: str) -> None:
        async with self._attachment_lock:
            record=self.data.get("attachments",{}).get(attachment_id)
            if not record or record.get("owner")!=user_id or record.get("message_id"): return
            self.data["attachments"].pop(attachment_id,None)
            try: await self.hass.async_add_executor_job(os.unlink,self._attachment_path(attachment_id))
            except OSError: pass

    async def abort_uploads(self) -> None:
        async with self._attachment_lock:
            upload_ids=list(self._uploads); self._uploads.clear()
            for attachment_id in upload_ids:
                try: await self.hass.async_add_executor_job(os.unlink,self._attachment_path(attachment_id,True))
                except OSError: pass

    async def read_attachment(self, user_id: str, attachment_id: str, offset: int, admins: set[str]) -> tuple[bytes, int]:
        record=self.data["attachments"].get(attachment_id)
        if not record or not record.get("message_id") or not self.domain.can_view(record["channel_id"],user_id,admins): raise PermissionError("attachment_access")
        if isinstance(offset,bool) or not isinstance(offset,int) or not 0 <= offset <= record["size"]: raise ValueError("invalid_attachment_offset")
        length=min(ATTACHMENT_CHUNK_SIZE,record["size"]-offset)
        def read():
            with open(self._attachment_path(attachment_id),"rb") as handle: handle.seek(offset); return handle.read(length)
        return await self.hass.async_add_executor_job(read), record["size"]

    async def async_cleanup_attachments(self) -> None:
        live={message.get("attachment_id") for message in self.data["messages"].values() if not message.get("deleted") and message.get("attachment_id")}; now=time.time()
        async with self._attachment_lock:
            stale=[attachment_id for attachment_id,record in self.data.get("attachments",{}).items() if (record.get("message_id") and attachment_id not in live) or (not record.get("message_id") and now-float(record.get("created",0))>3600)]
            expired=[attachment_id for attachment_id,record in self._uploads.items() if now-float(record.get("created",0))>3600]
            for attachment_id in stale: self.data["attachments"].pop(attachment_id,None)
            for attachment_id in expired: self._uploads.pop(attachment_id,None)
        for attachment_id,partial in [(item,False) for item in stale]+[(item,True) for item in expired]:
            try: await self.hass.async_add_executor_job(os.unlink,self._attachment_path(attachment_id,partial))
            except OSError: pass
