"""SPAIDER entrypoint. Starts the local web server and opens the UI in a browser.

Usage:
    py run.py [--host 127.0.0.1] [--port 8000] [--no-browser] [--reload]

This is the SPAIDER CONTROL UI (a web app — no separate window). The offensive tools run
in a separate Kali container via the `kali_server/` MCP server; enable it in Settings → Kali.
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
import webbrowser

import uvicorn


def _find_open_port(host: str, preferred: int) -> int:
    """Return `preferred` if free, otherwise the next free port (so startup never
    silently fails because the port is taken)."""
    for port in [preferred] + list(range(preferred + 1, preferred + 20)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    return preferred


def _open_browser(url: str) -> None:
    time.sleep(1.5)  # give uvicorn a moment to start accepting connections
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main() -> None:
    # Load the repo-root .env into the environment FIRST (before the server module is imported or any
    # env var is read), so settings like SPAIDER_REQUIRE_DISCLAIMER and the API keys can live in a
    # .env file instead of being exported in the shell. A real shell variable still wins. Under
    # --reload, uvicorn's worker is a child process that inherits this loaded environment.
    from spider._env import load_env

    load_env()

    parser = argparse.ArgumentParser(description="SPAIDER — autonomous penetration-testing web app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true", help="do not auto-open the browser")
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    bind_host = args.host
    port = args.port if args.reload else _find_open_port(bind_host if bind_host != "0.0.0.0" else "127.0.0.1", args.port)
    view_host = "127.0.0.1" if bind_host == "0.0.0.0" else bind_host
    url = f"http://{view_host}:{port}"

    banner = (
        "\n" + "=" * 56 + "\n"
        "  SPAIDER is running.\n"
        f"  Open this URL in your browser:  {url}\n"
        "  (this is a web app — there is no separate window)\n"
        "  Press CTRL+C to stop.\n"
        + "=" * 56 + "\n"
    )
    print(banner, flush=True)

    if not args.no_browser:
        threading.Thread(target=_open_browser, args=(url,), daemon=True).start()

    # When frozen into an exe, hand uvicorn the app object directly (the import-string
    # form requires re-importing the module, and --reload/workers can't be used).
    if getattr(sys, "frozen", False):
        from spider.server import app as _app

        uvicorn.run(_app, host=bind_host, port=port)
    else:
        uvicorn.run("spider.server:app", host=bind_host, port=port, reload=args.reload)


if __name__ == "__main__":
    main()
