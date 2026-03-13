import os
import gzip
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def load_wordlist(
    path: str | Path,
    *,
    ignore_comments: bool = True,
    deduplicate: bool = True,
    min_length: int = 1,
    max_length: int = 253,
    encoding: str = "utf-8",
) -> list[str]:
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"[wordlist] File not found: {path}")

    if not path.is_file():
        raise ValueError(f"[wordlist] Path is not a file: {path}")

    opener = gzip.open if path.suffix == ".gz" else open

    try:
        with opener(path, "rt", encoding=encoding, errors="ignore") as f:
            lines = f.readlines()
    except OSError as e:
        raise OSError(f"[wordlist] Failed to read '{path}': {e}") from e

    entries: list[str] = []
    seen: set[str] = set()

    for raw in lines:
        word = raw.strip()

        if not word:
            continue
        if ignore_comments and word.startswith("#"):
            continue
        if len(word) < min_length or len(word) > max_length:
            continue

        if deduplicate:
            if word in seen:
                continue
            seen.add(word)

        entries.append(word)

    if not entries:
        raise ValueError(f"[wordlist] '{path}' is empty or all entries were filtered out.")

    logger.debug("[wordlist] Loaded %d entries from '%s'", len(entries), path)
    return entries


def load_multiple_wordlists(*paths: str | Path, **kwargs) -> list[str]:
    seen: set[str] = set()
    merged: list[str] = []

    for path in paths:
        try:
            entries = load_wordlist(path, deduplicate=False, **kwargs)
        except (FileNotFoundError, ValueError) as e:
            logger.warning("%s — skipping.", e)
            continue

        for word in entries:
            if word not in seen:
                seen.add(word)
                merged.append(word)

    if not merged:
        raise ValueError("[wordlist] No entries loaded from any provided path.")

    logger.debug("[wordlist] Merged total: %d unique entries from %d files", len(merged), len(paths))
    return merged


def wordlist_stats(path: str | Path) -> dict:
    path = Path(path)
    total = unique = comments = 0
    min_len = float("inf")
    max_len = 0
    seen: set[str] = set()

    opener = gzip.open if path.suffix == ".gz" else open

    with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            word = raw.strip()
            if not word:
                continue
            if word.startswith("#"):
                comments += 1
                continue
            total += 1
            min_len = min(min_len, len(word))
            max_len = max(max_len, len(word))
            if word not in seen:
                seen.add(word)
                unique += 1

    return {
        "total":    total,
        "unique":   unique,
        "comments": comments,
        "min_len":  int(min_len) if total else 0,
        "max_len":  max_len,
        "path":     str(path),
    }