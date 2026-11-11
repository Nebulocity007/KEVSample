"""Stage 1 - Collect the CISA Known Exploited Vulnerabilities (KEV) feed.

Design choices:
* Public feed, no API key, no secrets.
* Every successful download is cached twice: a dated snapshot (for later trend
  analysis) and kev_latest.json (what the rest of the pipeline reads).
* Offline mode never touches the network: it uses the latest cache, then falls
  back to a small committed sample so a demo always works.
"""

from __future__ import annotations

import json
import shutil
import urllib.request
from datetime import date
from pathlib import Path

from . import RAW_DIR, SAMPLE_DIR

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
LATEST = RAW_DIR / "kev_latest.json"
SAMPLE = SAMPLE_DIR / "kev_sample.json"

# Generic client name: identifies the tool, not the person running it.
USER_AGENT = "fin-ti-pipeline/0.1 (+public KEV research demo)"


def validate(feed: dict) -> dict:
    """Minimal schema check so a captive portal / HTML error page is never cached."""
    if not isinstance(feed, dict) or not isinstance(feed.get("vulnerabilities"), list):
        raise ValueError("Not a KEV feed: missing 'vulnerabilities' list")
    if feed["vulnerabilities"] and "cveID" not in feed["vulnerabilities"][0]:
        raise ValueError("Not a KEV feed: records lack 'cveID'")
    return feed


def download(url: str = KEV_URL, timeout: int = 30) -> dict:
    """Fetch and parse the live feed. Raises on network or format errors."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return validate(json.loads(resp.read().decode("utf-8")))


def save_cache(feed: dict, raw_dir: Path = RAW_DIR) -> Path:
    """Write a dated snapshot plus kev_latest.json. Returns the snapshot path."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    snapshot = raw_dir / f"kev_{date.today():%Y%m%d}.json"
    snapshot.write_text(json.dumps(feed, indent=1), encoding="utf-8")
    shutil.copyfile(snapshot, raw_dir / "kev_latest.json")
    return snapshot


def load_cached(raw_dir: Path = RAW_DIR, sample: Path = SAMPLE) -> tuple[dict, str]:
    """Return (feed, source_label) from cache, else the bundled sample."""
    latest = raw_dir / "kev_latest.json"
    for path, label in ((latest, f"cache:{latest.name}"), (sample, "bundled sample")):
        if path.exists():
            return validate(json.loads(path.read_text(encoding="utf-8"))), label
    raise FileNotFoundError("No cached KEV feed and no bundled sample found")


def collect(offline: bool = False, refresh: bool = False) -> tuple[dict, str]:
    """Main entry point.

    offline=True  -> never download; cache, then sample.
    refresh=True  -> always download (fail loudly if the network is down).
    default       -> use today's cache if present, else download, else fall back.
    """
    if offline:
        return load_cached()

    today = RAW_DIR / f"kev_{date.today():%Y%m%d}.json"
    if today.exists() and not refresh:
        return load_cached()

    try:
        feed = download()
    except Exception as exc:  # network down, DNS, bad JSON, ...
        if refresh:
            raise
        feed, label = load_cached()
        return feed, f"{label} (download failed: {exc.__class__.__name__})"
    path = save_cache(feed)
    return feed, f"live download -> {path.name}"
