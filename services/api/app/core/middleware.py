"""Middleware: request IDs, rate limiting, and conservative security headers."""

from __future__ import annotations

import re
import threading
import time
import uuid
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

__all__ = ["RateLimitMiddleware", "RequestContextMiddleware"]

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns/echoes a safe request ID and adds basic security headers."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        incoming = request.headers.get("x-request-id", "")
        request_id = (
            incoming if _SAFE_REQUEST_ID.match(incoming) else f"req_{uuid.uuid4().hex[:16]}"
        )
        request.state.request_id = request_id
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window limiter for state-changing (non-GET) requests."""

    def __init__(self, app, requests_per_minute: int) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self.limit = max(1, requests_per_minute)
        self.window = 60.0
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        if not self._allow(client):
            return JSONResponse(
                status_code=429,
                content={"error": {"code": "rate_limited", "message": "Too many requests."}},
            )
        return await call_next(request)
