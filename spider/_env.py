"""Tiny, dependency-free ``.env`` loader (no python-dotenv).

The SPAIDER control app reads its settings from the process environment (``os.environ``) — e.g. the
hidden ``SPAIDER_REQUIRE_DISCLAIMER`` flag and the ``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY`` keys.
This loads ``KEY=VALUE`` pairs from a repo-root ``.env`` file into the environment at startup so you
don't have to export them in your shell. A real environment variable always WINS (we never override
one that's already set), matching the usual dotenv convention.

Supported syntax: blank lines, ``#`` comments, an optional ``export`` prefix, spaces around ``=``,
and single/double-quoted values (``KEY = "1"`` works). Inline ``#`` is NOT treated as a comment, so
values may safely contain ``#`` (e.g. proxy URLs or passwords).
"""
from __future__ import annotations

import os
from pathlib import Path

# repo root = the directory containing the `spider/` package (one up from this file).
_DEFAULT_ENV = Path(__file__).resolve().parent.parent / ".env"


def load_env(path: str | os.PathLike | None = None, *, override: bool = False) -> int:
    """Load KEY=VALUE pairs from `path` (default: repo-root ``.env``) into ``os.environ``.

    Returns the number of keys applied. Missing/unreadable file -> 0 (silently). By default an
    existing real environment variable is left untouched (``override=False``); pass
    ``override=True`` to let the file win.
    """
    p = Path(path) if path else _DEFAULT_ENV
    if not p.is_file():
        return 0
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return 0

    applied = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, val = line.partition("=")
        key = key.strip()
        if not key:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]  # strip surrounding matching quotes
        if override or key not in os.environ:
            os.environ[key] = val
            applied += 1
    return applied
