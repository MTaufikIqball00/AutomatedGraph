"""
Automated GraphRAG — One-Command Project Launcher
Initializes .env (if missing), verifies SQLite schema, automatically finds an unblocked
Windows/TCP port if the default port is reserved (fixes WinError 10013 / 10048),
opens the browser automatically once the server is healthy, and runs Uvicorn.
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path
import uvicorn

from backend.config import settings
from backend.database import init_db

ROOT_DIR = Path(__file__).resolve().parent

CANDIDATE_PORTS = [8765, 8080, 8501, 5050, 3000, 8888, 9000, 8000]


def can_bind_port(host: str, port: int) -> bool:
    """Test whether the current OS user can actually bind a TCP socket on (host, port)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def resolve_bindable_port(host: str, preferred_port: int) -> int:
    """
    Return `preferred_port` if bindable; otherwise automatically fall back to a verified
    unblocked port on Windows (preventing [Errno 10013] WinNAT/Hyper-V port exclusions).
    """
    if can_bind_port(host, preferred_port):
        return preferred_port

    print(
        f"[Launcher] Port {preferred_port} diblokir atau sedang dipakai di Windows (WinError 10013/10048). Mencari port alternatif..."
    )
    for port in CANDIDATE_PORTS:
        if port != preferred_port and can_bind_port(host, port):
            print(f"[Launcher] Menggunakan port alternatif yang tersedia: {port}")
            return port

    # Last resort: ask OS for any ephemeral free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        free_port = int(sock.getsockname()[1])
        print(f"[Launcher] Menggunakan port dinamis dari OS: {free_port}")
        return free_port


def ensure_env_file() -> None:
    """Create .env from .env.example if .env does not exist."""
    env_path = ROOT_DIR / ".env"
    example_path = ROOT_DIR / ".env.example"
    if not env_path.exists() and example_path.exists():
        shutil.copyfile(example_path, env_path)
        print("[Launcher] Created default .env from .env.example")


def ensure_tailwind_css(force_build: bool = False) -> None:
    """Build frontend/styles.css via Tailwind CLI if requested or if styles.css is missing."""
    css_path = ROOT_DIR / "frontend" / "styles.css"
    npm_cmd = shutil.which("npm")
    if (force_build or not css_path.exists()) and npm_cmd:
        print("[Launcher] Compiling Tailwind CSS (npm run build:css)...")
        subprocess.run([npm_cmd, "run", "build:css"], cwd=str(ROOT_DIR), check=False)


def wait_and_open_browser(url: str, health_url: str) -> None:
    """Poll /api/health until the server responds 200 OK, then open the default web browser."""
    for _ in range(30):
        try:
            with urllib.request.urlopen(health_url, timeout=1.5) as resp:
                if resp.status == 200:
                    print(f"[Launcher] Server aktif! Membuka browser di {url}")
                    webbrowser.open(url)
                    return
        except Exception:
            time.sleep(0.4)


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch Automated GraphRAG Enterprise Server")
    parser.add_argument("--host", default=settings.app_host, help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Preferred bind port (default: 8765)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")
    parser.add_argument("--build-css", action="store_true", help="Rebuild Tailwind CSS before starting")
    args = parser.parse_args()

    os.chdir(ROOT_DIR)
    ensure_env_file()
    ensure_tailwind_css(force_build=args.build_css)
    init_db()

    active_port = resolve_bindable_port(args.host, args.port)
    url = f"http://{args.host}:{active_port}"
    health_url = f"{url}/api/health"

    print("=" * 68)
    print("  AUTOMATED GRAPHRAG - ENTERPRISE WORKSPACE LAUNCHER")
    print("=" * 68)
    print(f"  Workspace URL : {url}")
    print(f"  API Docs URL  : {url}/docs")
    print(f"  Health Check  : {health_url}")
    print(f"  Database Path : {settings.sqlite_db_path}")
    print("=" * 68)

    if not args.no_browser:
        threading.Thread(
            target=wait_and_open_browser,
            args=(url, health_url),
            daemon=True,
        ).start()

    uvicorn.run(
        "backend.main:app",
        host=args.host,
        port=active_port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
