import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from src import server
from src.yeti_mcp.auth import BearerTokenMiddleware, is_loopback

CONTRIBUTE_TOOLS = {
    "add_observables_bulk",
    "tag_object",
    "link_objects",
    "create_entity",
    "create_indicator",
    "add_context",
}


async def _tools(mcp):
    async with Client(mcp) as client:
        return {tool.name: tool for tool in await client.list_tools()}


@pytest.mark.asyncio
async def test_read_profile_lists_only_read_tools():
    tools = await _tools(server.create_server("read"))
    assert len(tools) == 12
    assert not CONTRIBUTE_TOOLS & set(tools)
    assert all(tool.annotations.readOnlyHint for tool in tools.values())


@pytest.mark.asyncio
async def test_read_profile_refuses_contribute_tools():
    async with Client(server.create_server("read")) as client:
        with pytest.raises(ToolError, match="Unknown tool"):
            await client.call_tool(
                "add_observables_bulk",
                {"observables": [{"type": "ipv4", "value": "1.2.3.4"}]},
            )


@pytest.mark.asyncio
async def test_contribute_profile_lists_every_tool():
    tools = await _tools(server.create_server("contribute"))
    assert len(tools) == 18
    assert CONTRIBUTE_TOOLS <= set(tools)
    for name in CONTRIBUTE_TOOLS:
        assert tools[name].annotations.readOnlyHint is False
    assert tools["link_objects"].annotations.destructiveHint is True
    assert tools["add_observables_bulk"].annotations.destructiveHint is False


@pytest.mark.asyncio
async def test_every_tool_has_a_profile_tag_and_annotations():
    # A tool without a profile tag would be hidden from every profile.
    tools = await _tools(server.create_server("contribute"))
    for name, tool in tools.items():
        assert tool.annotations is not None, name
        assert tool.annotations.openWorldHint is False, name


@pytest.mark.asyncio
async def test_resources_are_in_the_read_profile():
    async with Client(server.create_server("read")) as client:
        uris = {str(resource.uri) for resource in await client.list_resources()}
    assert "yeti://supported_ioc_types" in uris


def test_default_profile_is_read():
    assert server.DEFAULT_PROFILE == "read"


def test_unknown_profile_is_refused():
    with pytest.raises(ValueError, match="Unknown profile"):
        server.create_server("admin")


def _app(token):
    async def ok(request):
        return PlainTextResponse("ok")

    async def ws(websocket):
        await websocket.accept()
        await websocket.send_text("ok")
        await websocket.close()

    return Starlette(
        routes=[Route("/", ok), WebSocketRoute("/ws", ws)],
        middleware=[Middleware(BearerTokenMiddleware, token=token)],
    )


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong"},
        {"Authorization": "Basic s3cret"},
        {"Authorization": "s3cret"},
    ],
)
def test_bearer_middleware_refuses_bad_or_missing_tokens(headers):
    response = TestClient(_app("s3cret")).get("/", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_bearer_middleware_accepts_the_token():
    response = TestClient(_app("s3cret")).get(
        "/", headers={"Authorization": "Bearer s3cret"}
    )
    assert response.status_code == 200
    assert response.text == "ok"


def test_bearer_middleware_needs_a_token():
    with pytest.raises(ValueError):
        BearerTokenMiddleware(None, token="")


@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.0.0.1", True),
        ("::1", True),
        ("localhost", True),
        ("0.0.0.0", False),
        ("::", False),
        ("192.0.2.10", False),
        ("yeti-mcp", False),
    ],
)
def test_is_loopback(host, expected):
    assert is_loopback(host) is expected


def test_main_refuses_non_local_http_without_token(monkeypatch):
    monkeypatch.delenv("YETI_MCP_AUTH_TOKEN", raising=False)
    monkeypatch.setattr(
        "sys.argv", ["server", "--transport", "http", "--mcp-host", "0.0.0.0"]
    )
    with pytest.raises(SystemExit, match="without authentication"):
        server.main()


def test_bearer_middleware_closes_unauthorized_websockets():
    with pytest.raises(WebSocketDisconnect) as closed:
        with TestClient(_app("s3cret")).websocket_connect("/ws") as websocket:
            websocket.receive_text()
    assert closed.value.code == 1008


def test_bearer_middleware_accepts_authorized_websockets():
    with TestClient(_app("s3cret")).websocket_connect(
        "/ws", headers={"Authorization": "Bearer s3cret"}
    ) as websocket:
        assert websocket.receive_text() == "ok"


@pytest.mark.parametrize("option", ["--mcp-host", "--mcp-port"])
def test_main_refuses_host_or_port_without_transport(monkeypatch, capsys, option):
    # These options used to start an SSE server; now they need --transport.
    value = "0.0.0.0" if option == "--mcp-host" else "8081"
    monkeypatch.setattr("sys.argv", ["server", option, value])
    with pytest.raises(SystemExit):
        server.main()
    assert "need --transport http or --transport sse" in capsys.readouterr().err


def test_main_refuses_an_unknown_profile_in_the_environment(monkeypatch, capsys):
    monkeypatch.setenv("YETI_MCP_PROFILE", "Read")
    monkeypatch.setattr("sys.argv", ["server"])
    with pytest.raises(SystemExit):
        server.main()
    assert "YETI_MCP_PROFILE must be one of" in capsys.readouterr().err


def test_an_unknown_profile_in_the_environment_falls_back_to_read(monkeypatch):
    monkeypatch.setenv("YETI_MCP_PROFILE", "Read")
    assert server._profile_from_env() == "read"


def test_main_warns_when_no_profile_is_set(monkeypatch, caplog):
    monkeypatch.delenv("YETI_MCP_PROFILE", raising=False)
    monkeypatch.setattr("sys.argv", ["server"])
    started = []
    monkeypatch.setattr(
        server.FastMCP, "run", lambda self, **kwargs: started.append(kwargs)
    )
    server.main()
    assert started == [{"transport": "stdio"}]
    assert "only the read tools are exposed" in caplog.text
