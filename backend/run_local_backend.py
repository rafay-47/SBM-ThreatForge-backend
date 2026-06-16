"""Convenience launcher for backend app in local development.

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
    app_entry = backend_dir / "app" / "index.py"

    venv_python = backend_dir.parent / ".venv" / "Scripts" / "python.exe"
    python_exec = str(venv_python if venv_python.exists() else Path(sys.executable))

    env = os.environ.copy()
    env.setdefault("DEPLOYMENT_MODE", "local")

    print(f"Starting backend with: {python_exec}")
    print(f"Entrypoint: {app_entry}")

    result = subprocess.run([python_exec, str(app_entry)], cwd=str(backend_dir), env=env)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
