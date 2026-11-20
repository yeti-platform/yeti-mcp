import argparse
import logging
import os
import sys

from fastmcp import FastMCP
from starlette.middleware import Middleware

from .yeti_mcp import resources
from .yeti_mcp import tools
from .yeti_mcp.auth import BearerTokenMiddleware, is_loopback


logger = logging.getLogger(__name__)

# Tool tags exposed by each profile. Tools tagged "read" only read from Yeti;
# tools tagged "contribute" add data to it. No tool deletes data.
PROFILES = {
    "read": {"read"},
    "contribute": {"read", "contribute"},
}
DEFAULT_PROFILE = "read"


def create_server(profile: str = DEFAULT_PROFILE) -> FastMCP:
    """Creates the MCP server, exposing only the tools of the given profile."""
    if profile not in PROFILES:
        raise ValueError(
            f"Unknown profile {profile!r}, expected one of: {', '.join(PROFILES)}"
        )
    server = FastMCP(
        name="yeti-mcp", dependencies=["yeti-api"], include_tags=PROFILES[profile]
    )
    server.mount(resources.mcp, prefix=None)
    server.mount(tools.mcp, prefix=None)
    return server


def _profile_from_env() -> str:
    """The profile named by YETI_MCP_PROFILE; the read profile if unset or unknown."""
    profile = os.environ.get("YETI_MCP_PROFILE") or DEFAULT_PROFILE
    if profile not in PROFILES:
        logger.error(f"Unknown YETI_MCP_PROFILE {profile!r}, using {DEFAULT_PROFILE!r}")
        return DEFAULT_PROFILE
    return profile


mcp = create_server(_profile_from_env())


def main():
    parser = argparse.ArgumentParser(description="MCP server for Yeti")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http", "sse"],
        help="Transport to use: stdio, http (streamable HTTP) or sse (legacy), "
        "default: stdio",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        help="Tools to expose: read (search and lookup tools only) or contribute "
        "(also tools that add data); default: $YETI_MCP_PROFILE or read",
    )
    parser.add_argument(
        "--mcp-host",
        type=str,
        help="Host to run MCP server on (http and sse only), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        help="Port to run MCP server on (http and sse only), default: 8081",
    )

    args = parser.parse_args()

    profile = args.profile or os.environ.get("YETI_MCP_PROFILE")
    if profile is None:
        profile = DEFAULT_PROFILE
        logger.warning(
            "No profile set: only the read tools are exposed. Use --profile "
            "contribute (or YETI_MCP_PROFILE=contribute) for the tools that add data."
        )
    elif profile not in PROFILES:
        parser.error(
            f"YETI_MCP_PROFILE must be one of: {', '.join(PROFILES)} (got {profile!r})"
        )

    transport = args.transport
    if transport is None:
        if args.mcp_host is not None or args.mcp_port is not None:
            # Before --transport existed, these options started an SSE server.
            parser.error(
                "--mcp-host and --mcp-port need --transport http or --transport sse "
                "(the server now defaults to stdio)"
            )
        transport = "stdio"
    host = args.mcp_host or "127.0.0.1"
    port = args.mcp_port or 8081

    server = create_server(profile)
    logger.info(f"Exposing the {profile!r} tool profile")

    if transport == "stdio":
        server.run(transport="stdio")
        return

    middleware = []
    token = os.environ.get("YETI_MCP_AUTH_TOKEN")
    if token:
        middleware.append(Middleware(BearerTokenMiddleware, token=token))
    elif is_loopback(host):
        logger.warning(
            "YETI_MCP_AUTH_TOKEN is not set: any local process can use this server"
        )
    else:
        sys.exit(
            f"Refusing to listen on {host} without authentication: set "
            "YETI_MCP_AUTH_TOKEN, or listen on 127.0.0.1."
        )

    logger.info(f"Running MCP server on {host}:{port}")
    try:
        server.run(
            transport=transport,
            host=host,
            port=port,
            middleware=middleware,
        )
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        return


if __name__ == "__main__":
    main()
