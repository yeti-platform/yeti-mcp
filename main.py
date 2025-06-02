import argparse
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from mcp.server.fastmcp import Context, FastMCP
from yeti.api import YetiApi

DEFAULT_YETI_ENDPOINT = "http://127.0.0.1:3000"

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    yeti_client: YetiApi


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    yeti_client = YetiApi(os.environ.get("YETI_ENDPOINT", DEFAULT_YETI_ENDPOINT))
    yeti_client.auth_api_key(os.environ.get("YETI_API_KEY"))
    try:
        yield AppContext(yeti_client=yeti_client)
    finally:
        pass


mcp = FastMCP("yeti-mcp", dependencies=["yeti-api"], lifespan=app_lifespan)


def _get_yeti_client() -> YetiApi:
    ctx: Context = mcp.get_context()
    if not hasattr(ctx.request_context, "lifespan_context"):
        raise RuntimeError("Lifespan context is not available")
    return ctx.request_context.lifespan_context.yeti_client


@mcp.tool()
def search_entities(
    name: str,
    entity_type: str | None = None,
    description: str | None = None,
    tags: list[str] | None = None,
    count: int = 100,
    page: int = 0,
) -> list:
    """
    Search for malware entities by name.

    Valid entity types include:

        {investigation, malware, tool, indicator, threat-actor, intrusion-set,
        campaign, course-of-action, identity, attack-pattern}

    Args:
        name: Return entities matching this name (substring).
            If the name is empty, it returns all entities.
        entity_type: The type of malware to filter by.
        description: A substring to search for in malware descriptions.
        tags: A list of tags to filter the malware by.
        count: The max number of results to return.
        page: The page number for pagination.

    Returns:
        A list of malware entities matching the name. If the number of
        results is lower than count, the last page has been reached.
    """
    kwargs = {"name": name, "count": count, "page": page}

    if entity_type:
        kwargs["entity_type"] = entity_type
    if description:
        kwargs["description"] = description
    if tags:
        kwargs["tags"] = tags

    client = _get_yeti_client()
    results = client.search_entities(**kwargs)
    return results


@mcp.tool()
def search_indicators(
    name: str,
    indicator_type: str | None = None,
    description: str | None = None,
    tags: list[str] | None = None,
    count: int = 100,
    page: int = 0,
) -> list:
    """
    Search for indicators by name.

    Valid indicator types include:

        {forensicartifact, regex, query, yara, suricata, sigma}

    Args:
        name: Return indicators matching this name (substring).
            If the name is empty, it returns all indicators.
        indicator_type: The type of indicator to filter by.
        description: A substring to search for in indicator descriptions.
        tags: A list of tags to filter the indicators by.
        count: The max number of results to return.
        page: The page number for pagination.

    Returns:
        list: A list of indicators matching the name. If the number of
        results is lower than count, the last page has been reached.
    """
    kwargs = {"name": name, "count": count, "page": page}

    if indicator_type:
        kwargs["indicator_type"] = indicator_type
    if description:
        kwargs["description"] = description
    if tags:
        kwargs["tags"] = tags

    client = _get_yeti_client()
    results = client.search_indicators(**kwargs)
    return results


@mcp.tool()
def get_neighbors(
    source: str, target_types: list[str] | None = None, count: int = 10, page: int = 0
) -> list:
    """
    Get neighbors of a source object by searching the Yeti graph. This can be
    used to find related objects based on the source object. (e.g. find TTPs
    related to a threat actor entity).

    Args:
        source: The <type>/ID notation of the source object for which to find neighbors, e.g. entities/1234.
        target_types: A list of target object (entities or indicators) types to filter neighbors by.
        count: The max number of results to return.
        page: The page number for pagination.

    Returns:
        A list of neighbors for the source object. If the number of results is lower than count,
        the last page has been reached.
    """
    client = _get_yeti_client()
    return client.search_graph(
        source,
        target_types=target_types,
        include_original=False,
        count=count,
        page=page,
    )


def main():
    parser = argparse.ArgumentParser(description="MCP server for Yeti")
    parser.add_argument(
        "--yeti-server",
        type=str,
        help=f"yeti server URL, default: {DEFAULT_YETI_ENDPOINT}",
        default=DEFAULT_YETI_ENDPOINT,
    )
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

    logger.info(f"Connecting to Yeti server at {args.yeti_server}")

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
