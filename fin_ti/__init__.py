"""fin_ti: a small, explainable threat-intel pipeline over the CISA KEV catalog.

Stages: collect -> store -> score -> tag -> report. Each stage is a plain module
so it can be demoed and tested on its own.
"""

from pathlib import Path

# Project root = parent of this package. All paths are resolved from here so the
# CLI works no matter which directory it is launched from.
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"          # cached downloads (gitignored)
SAMPLE_DIR = DATA_DIR / "sample"    # small committed snapshot for offline demos
CONFIG_DIR = ROOT / "config"
OUTPUT_DIR = ROOT / "output"
DB_PATH = DATA_DIR / "fin_ti.db"
