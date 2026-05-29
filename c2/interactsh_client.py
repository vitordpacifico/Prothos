import asyncio
import base64
import json
import secrets
import string
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

DEFAULT_SERVERS = ["oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me"]


@dataclass
class Interaction:
    protocol:    str
    unique_id:   str
    full_id:     str
    source_ip:   str
    timestamp:   str
    raw:         str          = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class InteractshReport:
    server:      str
    url:         Optional[str]       = None
    started_at:  str                 = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]      = None
    interactions: list[Interaction] = field(default_factory=list)
    errors:      list[str]          = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["interactions"] = [i.to_dict() for i in self.interactions]
        return d


def _rand(n: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


class _InteractshClient:
    def __init__(self, server: str):
        self.server = server
        self.correlation_id = _rand(20)
        self.secret = str(uuid.uuid4())
        self.private_key = None
        self.pub_b64 = None

    def _gen_keys(self) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            return False
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.pub_b64 = base64.b64encode(pub_pem).decode()
        return True

    async def register(self, client: httpx.AsyncClient) -> bool:
        r = await client.post(
            f"https://{self.server}/register",
            json={
                "public-key": self.pub_b64,
                "secret-key": self.secret,
                "correlation-id": self.correlation_id,
            },
            headers={"Content-Type": "application/json"},
            timeout=20,
        )
        return r.status_code == 200

    def url(self) -> str:
        return f"{self.correlation_id}{_rand(13)}.{self.server}"

    def _decrypt(self, aes_key_b64: str, data_b64: str) -> Optional[dict]:
        try:
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            aes_key = self.private_key.decrypt(
                base64.b64decode(aes_key_b64),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            blob = base64.b64decode(data_b64)
            iv, ct = blob[:16], blob[16:]
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            plain = decryptor.update(ct) + decryptor.finalize()
            return json.loads(plain.decode("utf-8", "replace"))
        except Exception:
            return None

    async def poll(self, client: httpx.AsyncClient) -> list[dict]:
        r = await client.get(
            f"https://{self.server}/poll",
            params={"id": self.correlation_id, "secret": self.secret},
            timeout=20,
        )
        if r.status_code != 200:
            return []
        body = r.json()
        aes_key = body.get("aes_key")
        out = []
        for item in body.get("data", []) or []:
            decrypted = self._decrypt(aes_key, item)
            if decrypted:
                out.append(decrypted)
        return out


def _print_interaction(i: Interaction):
    console.print(
        f"  [bold red][{i.protocol.upper()}][/bold red] "
        f"[cyan]{i.source_ip}[/cyan] → "
        f"[yellow]{i.full_id}[/yellow] [dim]{i.timestamp[11:19]}[/dim]"
    )


def _display(report: InteractshReport):
    console.print()
    console.print(Panel(
        f"[bold white]{report.url or report.server}[/bold white]  "
        f"[dim]interactions:[/dim] [yellow]{len(report.interactions)}[/yellow]",
        title="[bold red]Interactsh — Summary[/bold red]",
        border_style="red",
    ))

    if not report.interactions:
        console.print("[dim]    No interactions received.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red", border_style="dim")
    table.add_column("Protocol", style="white", width=10)
    table.add_column("Source",   style="cyan", width=18)
    table.add_column("ID",       style="yellow", min_width=30)
    table.add_column("Time",     style="dim", width=12)

    for i in report.interactions:
        table.add_row(i.protocol, i.source_ip, i.full_id[:40], i.timestamp[11:19])

    console.print(table)
    console.print()


async def _interactsh_async(server, duration, poll_interval) -> InteractshReport:
    report = InteractshReport(server=server)
    client_obj = _InteractshClient(server)

    if not client_obj._gen_keys():
        report.errors.append("cryptography not available — run: pip install cryptography")
        console.print("[red][!] cryptography missing[/red]")
        report.finished_at = datetime.now(timezone.utc).isoformat()
        return report

    async with httpx.AsyncClient(verify=True, headers={"User-Agent": "interactsh-client"}) as client:
        try:
            if not await client_obj.register(client):
                report.errors.append(f"registration failed on {server}")
                console.print(f"[red][!] Registration failed on {server}[/red]")
                report.finished_at = datetime.now(timezone.utc).isoformat()
                return report
        except Exception as e:
            report.errors.append(f"register error: {str(e)[:120]}")
            report.finished_at = datetime.now(timezone.utc).isoformat()
            return report

        report.url = client_obj.url()
        console.print(f"[bold green]    [+] OOB URL: {report.url}[/bold green]")
        console.print(f"[dim]    Polling every {poll_interval}s for {duration}s — Ctrl+C to stop[/dim]")

        elapsed = 0
        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Polling interactsh...", total=None)
            try:
                while elapsed < duration:
                    await asyncio.sleep(poll_interval)
                    elapsed += poll_interval
                    try:
                        for raw in await client_obj.poll(client):
                            inter = Interaction(
                                protocol=raw.get("protocol", "unknown"),
                                unique_id=raw.get("unique-id", client_obj.correlation_id),
                                full_id=raw.get("full-id", report.url or ""),
                                source_ip=raw.get("remote-address", ""),
                                timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
                                raw=json.dumps(raw)[:1000],
                            )
                            report.interactions.append(inter)
                            _print_interaction(inter)
                    except Exception as e:
                        report.errors.append(f"poll error: {str(e)[:100]}")
            except (KeyboardInterrupt, asyncio.CancelledError):
                console.print("[yellow]    [!] Interrupted, stopping poller[/yellow]")

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def run_interactsh_client(
    server:        str            = "oast.pro",
    duration:      int            = 300,
    poll_interval: int            = 5,
    proxy:         Optional[str]  = None,
    save_json:     Optional[str]  = None,
) -> InteractshReport:

    console.print(f"\n[bold red][*][/bold red] Interactsh Client → [bold white]{server}[/bold white]")

    try:
        report = asyncio.run(_interactsh_async(server, duration, poll_interval))
    except KeyboardInterrupt:
        report = InteractshReport(server=server)
        report.errors.append("interrupted")

    _display(report)

    if save_json:
        try:
            with open(save_json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            console.print(f"[dim][+] Saved to {save_json}[/dim]")
        except OSError as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")

    return report
