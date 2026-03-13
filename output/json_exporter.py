import json
import gzip
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from rich.console import Console

console = Console()

def _serialize(obj: Any) -> Any:
    if hasattr(obj, "to_dict"):
        return _serialize(obj.to_dict())
    if hasattr(obj, "__dataclass_fields__"):
        return _serialize(asdict(obj))
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize(i) for i in obj]
    if isinstance(obj, set):
        return sorted(_serialize(i) for i in obj)
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj

def export_json(
    data:       Any,
    path:       str | Path,
    *,
    compress:   bool = False,
    pretty:     bool = True,
    append:     bool = False,
    metadata:   bool = True,
) -> Path:
 
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = _serialize(data)

    if metadata and isinstance(payload, dict):
        payload["_meta"] = {
            "tool":      "Prothos",
            "exported":  datetime.now(timezone.utc).isoformat(),
            "version":   "1.0.0",
        }

    if append and path.exists() and not compress:
        try:
            with open(path, "r", encoding="utf-8") as f:
                existing = json.load(f)
            if isinstance(existing, list):
                existing.append(payload)
                payload = existing
            else:
                payload = [existing, payload]
        except Exception:
            pass

    indent = 2 if pretty else None

    if compress:
        gz_path = path if str(path).endswith(".gz") else Path(str(path) + ".gz")
        with gzip.open(gz_path, "wt", encoding="utf-8") as f:
            json.dump(payload, f, indent=indent, ensure_ascii=False)
        console.print(f"[dim][+] JSON saved → {gz_path} "
                      f"({gz_path.stat().st_size // 1024}KB compressed)[/dim]")
        return gz_path

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=indent, ensure_ascii=False)

    console.print(f"[dim][+] JSON saved → {path} "
                  f"({path.stat().st_size // 1024}KB)[/dim]")
    return path


def export_json_multi(
    reports:  dict[str, Any],
    path:     str | Path,
    **kwargs,
) -> Path:
    
    merged = {key: _serialize(val) for key, val in reports.items()}
    return export_json(merged, path, **kwargs)


def load_json(path: str | Path) -> Any:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"[json] File not found: {path}")

    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as f:
        return json.load(f)