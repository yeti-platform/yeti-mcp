import argparse
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from mcp.server.fastmcp import Context, FastMCP
from yeti.api import YetiApi, SUPPORTED_IOC_TYPES

from typing import Any


# Timesketch - only here to test

from timesketch_api_client.client import TimesketchApi
from timesketch_api_client import search
from timesketch_api_client import aggregation

# end Timesketch imports

DEFAULT_YETI_ENDPOINT = "http://127.0.0.1:3000"

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    yeti_client: YetiApi
    ts_client: TimesketchApi


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    yeti_client = YetiApi(os.environ.get("YETI_ENDPOINT", DEFAULT_YETI_ENDPOINT))
    yeti_client.auth_api_key(os.environ.get("YETI_API_KEY"))
    host_uri = f"http://{os.environ.get('TIMESKETCH_HOST')}:{os.environ.get('TIMESKETCH_PORT', '5000')}/"
    ts_client = TimesketchApi(
        host_uri=host_uri,
        username=os.environ.get("TIMESKETCH_USER"),
        password=os.environ.get("TIMESKETCH_PASSWORD"),
    )
    try:
        yield AppContext(yeti_client=yeti_client, ts_client=ts_client)
    finally:
        pass


mcp = FastMCP("yeti-mcp", dependencies=["yeti-api"], lifespan=app_lifespan)


def _get_yeti_client() -> YetiApi:
    ctx: Context = mcp.get_context()
    if not hasattr(ctx.request_context, "lifespan_context"):
        raise RuntimeError("Lifespan context is not available")
    return ctx.request_context.lifespan_context.yeti_client


def _get_timesketch_client():
    ctx: Context = mcp.get_context()
    if not hasattr(ctx.request_context, "lifespan_context"):
        raise RuntimeError("Lifespan context is not available")
    return ctx.request_context.lifespan_context.ts_client


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


@mcp.tool()
async def discover_data_types(sketch_id: int):
    """
    Discover data types in a Timesketch sketch.

    Args:
        sketch_id: The ID of the Timesketch sketch to discover data types from.

    Returns:
        A list of dictionaries containing data type information, including:
        - data_type: The name of the data type.
        - count: The number of events for that data type.
    """

    sketch = _get_timesketch_client().get_sketch(sketch_id)
    aggregator_name = "field_bucket"
    aggregator_params = {
        "field": "data_type",
        "limit": "10000",
    }

    # Use the sketch object's run_aggregator method
    aggregation_result: aggregation.Aggregation = sketch.run_aggregator(
        aggregator_name=aggregator_name, aggregator_parameters=aggregator_params
    )
    return aggregation_result.data.get("objects")[0]["field_bucket"]["buckets"]


@mcp.tool()
async def search_timesketch_events(
    sketch_id: int,
    query: str,
    filter_return_fields: list[str] | None = None,
    max_events: int | None = None,
    sort: str = "asc",
    starred: bool = False,
) -> list[dict[str, Any]]:
    """
    Returns a list of event dictionaries (limited by max_events, if provided).

        Events always contain the following fields:
        • datetime (useful for sorting)
        • data_type (useful for filtering).
        • message

        Always put double quotes around field values in queries (so data_type:"syslog:cron:task_run"
        instead of data_type:syslog:cron:task_run)'

        Examples:
        • Datatype       `data_type:"apache:access_log:entry"`'
        • Field match    `filename:*.docx`
        • Exact phrase   `"mimikatz.exe"`'
        • Boolean        `(ssh AND error) OR tag:bruteforce`
        • Date range     `datetime:[2025-04-01 TO 2025-04-02]`
        • Wildcard       `user:sam*`
        • Regex          `host:/.*\\.corp\\.internal/`

    Args:
        sketch_id: The ID of the Timesketch sketch to search.
        query: The Lucene/OpenSearch query string to use for searching.
        filter_return_fields: A list of fields to return in the results. If None, defaults to
            "datetime, message, data_type, tag, yara_match, sha256_hash".
        max_events: Optional maximum number of events to return. If None, returns all matching events.
        sort: Sort order for datetime field, either "asc" or "desc". Default is "asc".
        starred: If True, only return starred events. If False, return all events.

    Returns:
        A list of dictionaries representing the events found in the sketch.
        Each dictionary contains fields like datetime, data_type, tag, message,
        and optionally yara_match and sha256_hash if they are present in the results.
    """

    sketch = _get_timesketch_client().get_sketch(sketch_id)
    if not sketch:
        raise ValueError(f"Sketch with ID {sketch_id} not found.")

    search_instance = search.Search(sketch=sketch)
    search_instance.query_string = query
    if max_events:
        search_instance.max_entries = max_events
    search_instance.return_fields = (
        "datetime, message, data_type, tag, yara_match, sha256_hash"
    )
    if sort == "desc":
        search_instance.order_descending()
    else:
        search_instance.order_ascending()

    if starred:
        star_chip = search.LabelChip()
        star_chip.use_star_label()
        search_instance.add_chip(star_chip)

    result_df = search_instance.table

    if result_df.empty:
        return []

    extra_cols = []
    if "yara_match" in result_df.columns:
        result_df["yara_match"] = result_df["yara_match"].fillna(
            "N/A"
        )  # Keep NaN handling
        extra_cols.append("yara_match")

    if "sha256_hash" in result_df.columns:
        result_df["sha256_hash"] = result_df["sha256_hash"].fillna("N/A")
        extra_cols.append("sha256_hash")

    results_dict = result_df[
        ["datetime", "data_type", "tag", "message"] + extra_cols
    ].to_dict(orient="records")

    if filter_return_fields:
        results_dict = [
            {k: v for k, v in r.items() if k in filter_return_fields}
            for r in results_dict
        ]

    return results_dict


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
