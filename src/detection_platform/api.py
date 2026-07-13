"""Dependency-light local API and dashboard for measured replay results."""

from __future__ import annotations

import json
from datetime import date
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Type
from urllib.parse import unquote, urlparse

from . import __version__
from .bundle import default_bundle_root
from .corpus import load_corpus, verify_provenance
from .errors import DetectionPlatformError, ValidationError
from .jsonutil import loads_json
from .manifest import load_manifests, public_manifest
from .models import to_jsonable
from .replay import run_replay


MAX_REQUEST_BYTES = 16_384
_WEB_DIR = Path(__file__).with_name("web")


def _parse_as_of(value: Any) -> date:
    if not isinstance(value, str):
        raise ValueError("as_of must be an ISO date string")
    return date.fromisoformat(value)


def handler_for(bundle_root: Path) -> Type[BaseHTTPRequestHandler]:
    configured_bundle = bundle_root.resolve()

    class Handler(BaseHTTPRequestHandler):
        server_version = "DetectionPlatform/0.1"

        def log_message(self, format: str, *args: object) -> None:
            return

        def _headers(
            self, status: int, content_type: str, length: int, cache: str = "no-store"
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                "img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            )
            self.end_headers()

        def _json(self, status: int, value: Any) -> None:
            body = (
                json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n"
            ).encode("utf-8")
            self._headers(status, "application/json; charset=utf-8", len(body))
            self.wfile.write(body)

        def _asset(self, path: Path, content_type: str) -> None:
            try:
                body = path.read_bytes()
            except FileNotFoundError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "asset_not_found"})
                return
            self._headers(HTTPStatus.OK, content_type, len(body), "public, max-age=300")
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = unquote(urlparse(self.path).path)
            try:
                if path == "/":
                    self._asset(_WEB_DIR / "index.html", "text/html; charset=utf-8")
                elif path == "/assets/app.js":
                    self._asset(_WEB_DIR / "app.js", "text/javascript; charset=utf-8")
                elif path == "/assets/styles.css":
                    self._asset(_WEB_DIR / "styles.css", "text/css; charset=utf-8")
                elif path == "/api/v1/health":
                    self._json(
                        HTTPStatus.OK,
                        {
                            "status": "ok",
                            "version": __version__,
                            "deployment_mode": "simulation-only",
                        },
                    )
                elif path == "/api/v1/rules":
                    self._json(
                        HTTPStatus.OK,
                        {
                            "rules": [
                                public_manifest(item)
                                for item in load_manifests(configured_bundle)
                            ]
                        },
                    )
                elif path == "/api/v1/datasets":
                    _, datasets = load_corpus(configured_bundle)
                    self._json(
                        HTTPStatus.OK,
                        {
                            "datasets": to_jsonable(datasets),
                            "provenance": verify_provenance(configured_bundle),
                        },
                    )
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            except DetectionPlatformError as exc:
                self._json(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    {"error": type(exc).__name__, "detail": str(exc)},
                )

        def do_POST(self) -> None:  # noqa: N802
            path = unquote(urlparse(self.path).path)
            if path != "/api/v1/replay":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            if self.headers.get_content_type() != "application/json":
                self._json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"error": "application_json_required"},
                )
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_content_length"})
                return
            if not 0 < length <= MAX_REQUEST_BYTES:
                self._json(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {"error": "request_size_rejected"},
                )
                return
            try:
                raw = loads_json(
                    self.rfile.read(length).decode("utf-8"), "API request body"
                )
                if not isinstance(raw, dict) or set(raw) != {"as_of"}:
                    raise ValueError("request must contain only as_of")
                report = run_replay(configured_bundle, _parse_as_of(raw["as_of"]))
                self._json(HTTPStatus.OK, report)
            except UnicodeDecodeError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            except ValidationError as exc:
                self._json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "invalid_json", "detail": str(exc)},
                )
            except ValueError as exc:
                self._json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "invalid_request", "detail": str(exc)},
                )
            except DetectionPlatformError as exc:
                self._json(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    {"error": type(exc).__name__, "detail": str(exc)},
                )

    return Handler


def create_server(
    host: str, port: int, bundle_root: Path | None = None
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(
        (host, port), handler_for(bundle_root or default_bundle_root())
    )
    server.daemon_threads = True
    return server


def serve(host: str, port: int, bundle_root: Path | None = None) -> None:
    server = create_server(host, port, bundle_root)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
