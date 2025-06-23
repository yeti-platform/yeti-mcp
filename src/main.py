import argparse
import logging

from fastmcp import FastMCP

from yeti_mcp import resources
from yeti_mcp import tools


logger = logging.getLogger(__name__)


mcp = FastMCP(name="yeti-mcp", dependencies=["yeti-api"])

mcp.mount(resources.mcp, prefix=None)
mcp.mount(tools.mcp, prefix=None)


def main():
    parser = argparse.ArgumentParser(description="MCP server for Yeti")
    parser.add_argument(
        "--mcp-host",
        type=str,
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
        default="127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        help="Port to run MCP server on (only used for sse), default: 8081",
        default=8081,
    )

    args = parser.parse_args()

    logger.info(f"Running MCP server on {args.mcp_host}:{args.mcp_port}")
    try:
        mcp.settings.port = args.mcp_port
        mcp.settings.host = args.mcp_host
        mcp.run(transport="sse")
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        return


if __name__ == "__main__":
    main()
