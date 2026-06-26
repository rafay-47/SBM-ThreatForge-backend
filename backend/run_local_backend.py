"""Convenience launcher for backend app in local development.

Runs backend/app/main.py via uvicorn, mirroring how the sentry and
threat_designer services are started.

Prefers the workspace virtual environment interpreter when available,
falls back to the current Python executable otherwise.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    backend_dir = Path(__file__).resolve().parent
    app_dir = backend_dir / "app"

    venv_python = backend_dir.parent / ".venv" / "Scripts" / "python.exe"
    python_exec = str(venv_python if venv_python.exists() else Path(sys.executable))

    env = os.environ.copy()
    env.setdefault("DEPLOYMENT_MODE", "local")

    port = env.get("PORT", "8000")
    workers = env.get("WORKERS", "1")

    print(f"Starting backend app with: {python_exec}")
    print(f"App directory: {app_dir}")
    print(f"Listening on http://0.0.0.0:{port}")

    cmd = [
        python_exec,
        "-m",
        "uvicorn",
        "main:app",
        "--host",
        "0.0.0.0",
        "--port",
        port,
    ]

    if workers != "1":
        cmd.extend(["--workers", workers])
        print(f"Running Uvicorn with {workers} workers (reload disabled)")
    else:
        cmd.append("--reload")
        print("Running Uvicorn in reload mode (single worker)")

    result = subprocess.run(
        cmd,
        cwd=str(app_dir),
        env=env,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
