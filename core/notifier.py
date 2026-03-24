import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from rich.console import Console

console = Console()

@dataclass
class Notification:
    title:     str
    message:   str
    severity:  str        = "info"
    timestamp: str        = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class Notifier:

    SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

    def __init__(self, min_severity: str = "high"):
        self.min_severity      = min_severity
        self._telegram_token:  Optional[str] = None
        self._telegram_chat:   Optional[str] = None
        self._discord_webhook: Optional[str] = None
        self._slack_webhook:   Optional[str] = None
        self._history:         list[Notification] = []

    def set_telegram(self, token: str, chat_id: str):
        self._telegram_token = token
        self._telegram_chat  = chat_id

    def set_discord(self, webhook: str):
        self._discord_webhook = webhook

    def set_slack(self, webhook: str):
        self._slack_webhook = webhook

    def _should_notify(self, severity: str) -> bool:
        try:
            return (
                self.SEVERITY_ORDER.index(severity.lower())
                >= self.SEVERITY_ORDER.index(self.min_severity.lower())
            )
        except ValueError:
            return True

    def _format_message(self, notif: Notification) -> str:
        return (
            f"[{notif.severity.upper()}] {notif.title}\n"
            f"{notif.message}\n"
            f"{notif.timestamp}"
        )

    async def _send_telegram(self, notif: Notification):
        if not self._telegram_token or not self._telegram_chat:
            return
        try:
            import httpx
            url  = f"https://api.telegram.org/bot{self._telegram_token}/sendMessage"
            text = self._format_message(notif)
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(url, json={
                    "chat_id":    self._telegram_chat,
                    "text":       text,
                    "parse_mode": "Markdown",
                })
        except Exception as e:
            console.print(f"[dim][!] Telegram failed: {e}[/dim]")

    async def _send_discord(self, notif: Notification):
        if not self._discord_webhook:
            return
        try:
            import httpx
            color = {
                "critical": 0xe63946,
                "high":     0xf4845f,
                "medium":   0xffd166,
                "low":      0x666666,
                "info":     0x48cae4,
            }.get(notif.severity, 0xffffff)

            payload = {
                "embeds": [{
                    "title":       f"[{notif.severity.upper()}] {notif.title}",
                    "description": notif.message,
                    "color":       color,
                    "footer":      {"text": f"Prothos - {notif.timestamp}"},
                }]
            }
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(self._discord_webhook, json=payload)
        except Exception as e:
            console.print(f"[dim][!] Discord failed: {e}[/dim]")

    async def _send_slack(self, notif: Notification):
        if not self._slack_webhook:
            return
        try:
            import httpx
            text = f"[{notif.severity.upper()}] {notif.title}\n{notif.message}"
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(self._slack_webhook, json={"text": text})
        except Exception as e:
            console.print(f"[dim][!] Slack failed: {e}[/dim]")

    async def notify(
        self,
        title:    str,
        message:  str,
        severity: str = "info",
    ):
        notif = Notification(title=title, message=message, severity=severity)
        self._history.append(notif)

        if not self._should_notify(severity):
            return

        await asyncio.gather(
            self._send_telegram(notif),
            self._send_discord(notif),
            self._send_slack(notif),
            return_exceptions=True,
        )

    def notify_sync(self, title: str, message: str, severity: str = "info"):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(self.notify(title, message, severity))
            else:
                loop.run_until_complete(self.notify(title, message, severity))
        except Exception:
            asyncio.run(self.notify(title, message, severity))

    def notify_finding(self, finding):
        self.notify_sync(
            title=finding.title,
            message=(
                f"Module: {finding.module}\n"
                f"Target: {finding.target}\n"
                + (f"URL: {finding.url}\n" if finding.url else "")
                + (f"Evidence: {finding.evidence}" if finding.evidence else "")
            ),
            severity=finding.severity,
        )

    @property
    def history(self) -> list[Notification]:
        return self._history

    @property
    def stats(self) -> dict:
        return {
            "total":        len(self._history),
            "telegram":     bool(self._telegram_token),
            "discord":      bool(self._discord_webhook),
            "slack":        bool(self._slack_webhook),
            "min_severity": self.min_severity,
        }

_global_notifier: Optional[Notifier] = None

def get_notifier(min_severity: str = "high") -> Notifier:
    global _global_notifier
    if _global_notifier is None:
        _global_notifier = Notifier(min_severity=min_severity)
    return _global_notifier