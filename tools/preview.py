#!/usr/bin/env python3
"""Run the edgekit panel locally so the UI can be looked at while it is being changed.

    python3 tools/preview.py                    # populated server, http://127.0.0.1:8099
    python3 tools/preview.py --scenario empty   # fresh install, nothing configured yet
    python3 tools/preview.py --scenario degraded

Templates and CSS reload on their own — Jinja re-reads a template when its file changes and
StaticFiles serves from disk, so editing an .html or app.css and refreshing is enough.
Pass --reload to also restart on Python changes.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

BANNER = """
  edgekit panel preview
  ---------------------
  scenario   {scenario}
  url        http://{host}:{port}
  sign in    http://{host}:{port}/_preview/login      (no password needed)
             or admin / {password}

  switch scenario without restarting:
    /_preview/scenario/populated
    /_preview/scenario/healthy
    /_preview/scenario/empty
    /_preview/scenario/degraded

  state lives in .preview/ — delete it to start clean. Nothing touches /etc or /var.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", default="populated",
                        choices=("populated", "healthy", "empty", "degraded"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--reload", action="store_true",
                        help="restart the server when Python files change")
    args = parser.parse_args()

    os.environ["EDGEKIT_PREVIEW_SCENARIO"] = args.scenario
    os.environ.setdefault("EDGEKIT_ROOT", str(REPO_ROOT / ".preview" / "root"))
    # Lets uvicorn's reloader re-import tools.preview_app in its child process.
    os.environ["PYTHONPATH"] = os.pathsep.join(
        [str(REPO_ROOT), os.environ.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    sys.path.insert(0, str(REPO_ROOT))

    try:
        import uvicorn
    except ModuleNotFoundError:
        print("uvicorn is not installed. Try: .venv/bin/pip install -e '.[dev]'", file=sys.stderr)
        return 1

    from tools.preview_app import PASSWORD

    print(BANNER.format(scenario=args.scenario, host=args.host, port=args.port,
                        password=PASSWORD))

    if args.reload:
        uvicorn.run(
            "tools.preview_app:app",
            host=args.host,
            port=args.port,
            reload=True,
            reload_dirs=[str(REPO_ROOT / "src"), str(REPO_ROOT / "tools")],
            log_level="warning",
        )
    else:
        from tools.preview_app import app

        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
