import hmac
import ipaddress

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


class BearerTokenMiddleware:
    """Refuses requests that don't carry `Authorization: Bearer <token>`.

    Plain ASGI rather than BaseHTTPMiddleware, so streamed (SSE) responses
    pass through untouched. Only lifespan events skip the check.
    """

    def __init__(self, app: ASGIApp, token: str) -> None:
        if not token:
            raise ValueError("The bearer token must not be empty")
        self.app = app
        self._token = token.encode()

    def _authorized(self, scope: Scope) -> bool:
        header = dict(scope.get("headers") or []).get(b"authorization", b"")
        scheme, _, value = header.partition(b" ")
        return scheme.lower() == b"bearer" and hmac.compare_digest(
            value.strip(), self._token
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan" or self._authorized(scope):
            await self.app(scope, receive, send)
        elif scope["type"] == "http":
            response = JSONResponse(
                {"error": "unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
        else:
            # A websocket, or any other connection type: close it unanswered.
            await send({"type": "websocket.close", "code": 1008})


def is_loopback(host: str) -> bool:
    """Whether binding to `host` only accepts connections from this machine."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
