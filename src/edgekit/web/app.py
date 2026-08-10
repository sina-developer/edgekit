"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .. import __version__
from ..config import Config, load_config
from ..db import init_db
from . import deps
from .routers import api, auth, dashboard, hosts, peers, settings
from .templating import templates

log = logging.getLogger("edgekit.web")

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    log.info("edgekit panel %s ready", __version__)
    yield


def create_app(config: Config | None = None) -> FastAPI:
    deps.configure(config or load_config())

    app = FastAPI(
        title="edgekit",
        version=__version__,
        docs_url=None,  # the panel is the interface; an unauthenticated /docs is a liability
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    app.include_router(auth.router)
    app.include_router(dashboard.router)
    app.include_router(peers.router)
    app.include_router(hosts.router)
    app.include_router(settings.router)
    app.include_router(api.router)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        # Everything is served from this origin; no external fetches are needed or allowed.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        return response

    @app.exception_handler(deps.RedirectToLogin)
    async def _login_redirect(request: Request, exc: deps.RedirectToLogin):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "authentication required"}, status_code=401)
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        return templates.TemplateResponse(
            request,
            "error.html",
            {"status_code": exc.status_code, "detail": exc.detail},
            status_code=exc.status_code,
        )

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> JSONResponse:
        """Unauthenticated liveness probe. Reveals nothing beyond 'the process is up'."""
        return JSONResponse({"status": "ok", "version": __version__})

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> HTMLResponse:
        return HTMLResponse(status_code=204)

    return app
