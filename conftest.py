"""
Ensure the src/ layout is on sys.path so tests can import securegitx
without requiring `pip install -e .` first.
"""
import sys
from pathlib import Path

src = Path(__file__).parent / "src"
if str(src) not in sys.path:
    sys.path.insert(0, str(src))
