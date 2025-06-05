import argparse
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from fastmcp import Context, FastMCP
from yeti.api import YetiApi, SUPPORTED_IOC_TYPES

from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    yeti_client: YetiApi


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    yeti_endpoint = os.environ.get("YETI_ENDPOINT")
    yeti_api_key = os.environ.get("YETI_API_KEY")
    if not yeti_endpoint or not yeti_api_key:
        logger.error("YETI_ENDPOINT and YETI_API_KEY environment variables must be set")
        raise ValueError("Missing Yeti API configuration")

    yeti_client = YetiApi(yeti_endpoint)
    yeti_client.auth_api_key(yeti_api_key)

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


@mcp.resource("yeti://supported_ioc_types")
def get_supported_ioc_types() -> list[str]:
    """
    Get the list of supported IOC types.

    Returns:
        A list of supported IOC types.
    """
    return SUPPORTED_IOC_TYPES


@mcp.tool()
def match_observables(observables: list[str]) -> list:
    """
    Match observables against Yeti's database.

    Args:
        observables: A list of observables to search for.

    Returns:
        A list of observables found in Yeti.
    """
    client = _get_yeti_client()
    results = client.match_observables(observables)
    return results


@mcp.tool()
def add_observables_bulk(
    observables: list[dict[str, str]],
    tags: list[str] | None = None,
) -> list:
    """
    Add observables to Yeti.

    All tags will be applied to all observables, so use with caution. If different
    tags are needed for each observable, use several calls to `add_observables_bulk` instead.

    Args:
        observables: A list of observables to add. Observables should be dictionaries
            with keys like "type" and "value", e.g. [{"type": "ip", "value": "8.8.8.8"}].
            A list of valid types can be found in the `get_supported_ioc_types` resource.
        tags: A list of tags to associate with the observables. Only use
            high-relevance tags related to the malicious nature of the observables.
            (e.g. malware name, role of the IOC (C2, persistence, staging, etc.))

    Returns:
        A list of added observables.
    """
    client = _get_yeti_client()
    results = client.add_observables_bulk(observables, tags=tags)
    return results


@mcp.tool()
def link_objects(
    source: dict[str, Any],
    target: dict[str, Any],
    link_type: str = "related",
    description: str | None = None,
) -> dict:
    """
    Link two objects in Yeti.

    As a general rule, if linking Observables (e.g. hashes, IP addresses, domains),
    to Entities (e.g. threat actors, malware, incidents, intrusion sets), use the
    obseravble as a source and a relevant description, such as "used by" or "seen in".

    A link with the same source, target and link_type will be overwritten.

    e.g. 8.8.8.8 (source) -> threat actor (target) with link_type "related" and description "used by".
    <hash> (source) -> <malware> (target) with link_type "related" and description "seen in".

    Args:
        source: The source object.
        target: The target object.
        link_type: The type of link to create (default is "related").
        description: An optional description for the link.

    Returns:
        A dictionary containing the details of the created link.
    """
    client = _get_yeti_client()
    result = client.link_objects(source, target, link_type, description)
    return result


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
    source: str,
    target_types: list[str] | None = None,
    direction: str = "outbound",
    count: int = 10,
    page: int = 0,
) -> list:
    """
    Get neighbors of an object by searching the Yeti graph. This can be
    used to find related objects based on the source object. (e.g. find TTPs
    related to a threat actor entity).

    Args:
        source: The <type>/ID notation of the source object for which to find neighbors, e.g. entities/1234.
        dierction: The direction of the search, either "inbound" or "outbound" or "any".
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
        direction=direction,
        count=count,
        page=page,
    )


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
