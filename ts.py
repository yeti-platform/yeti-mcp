import argparse
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import Context, FastMCP
from timesketch_api_client import aggregation, search
from timesketch_api_client.client import TimesketchApi

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    ts_client: TimesketchApi


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    host_uri = f"http://{os.environ.get('TIMESKETCH_HOST')}:{os.environ.get('TIMESKETCH_PORT', '5000')}/"
    ts_client = TimesketchApi(
        host_uri=host_uri,
        username=os.environ.get("TIMESKETCH_USER"),
        password=os.environ.get("TIMESKETCH_PASSWORD"),
    )
    try:
        yield AppContext(ts_client=ts_client)
    finally:
        pass


mcp = FastMCP("timesketch-mcp", dependencies=["yeti-api"], lifespan=app_lifespan)


def _get_timesketch_client():
    ctx: Context = mcp.get_context()
    if not hasattr(ctx.request_context, "lifespan_context"):
        raise RuntimeError("Lifespan context is not available")
    return ctx.request_context.lifespan_context.ts_client


# Timesketch tools


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
    Search a Timesketch sketch and return a list of event dictionaries
      (limited by max_events, if provided).

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
        • Regex          `host:/.*\\.google\\.com/`

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
        result_df["yara_match"] = result_df["yara_match"].fillna("N/A")
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
    parser = argparse.ArgumentParser(description="MCP server for Timesketch")
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
