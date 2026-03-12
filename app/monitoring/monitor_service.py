"""
Monitoring service - track domains, detect new activity, trigger alerts
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Awaitable
import httpx


@dataclass
class MonitoredTarget:
    """Target being monitored"""
    target: str
    webhook_url: str | None = None
    email: str | None = None
    last_scan: dict | None = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


# In-memory store - use Redis/DB for production
_monitored: dict[str, MonitoredTarget] = {}


class MonitorService:
    """Manages monitoring of threat targets"""

    @staticmethod
    def add(target: str, webhook_url: str | None = None, email: str | None = None) -> dict:
        """Add target to monitoring"""
        key = target.strip().lower()
        _monitored[key] = MonitoredTarget(target=key, webhook_url=webhook_url, email=email)
        return {"target": key, "status": "monitoring", "webhook": bool(webhook_url), "email": bool(email)}

    @staticmethod
    def remove(target: str) -> dict:
        """Remove target from monitoring"""
        key = target.strip().lower()
        if key in _monitored:
            del _monitored[key]
        return {"target": key, "status": "removed"}

    @staticmethod
    def list_targets() -> list[dict]:
        """List monitored targets"""
        return [
            {"target": t.target, "webhook": bool(t.webhook_url), "email": bool(t.email)}
            for t in _monitored.values()
        ]

    @staticmethod
    async def trigger_webhook(url: str, payload: dict):
        """Send alert to webhook"""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(url, json=payload)
        except Exception:
            pass  # Log in production
