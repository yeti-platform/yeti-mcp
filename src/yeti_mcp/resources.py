from yeti.api import SUPPORTED_IOC_TYPES

from fastmcp import FastMCP

mcp = FastMCP(name="yeti-resources")


@mcp.resource("yeti://supported_ioc_types")
def get_supported_ioc_types() -> list[str]:
    """
    Get the list of supported IOC types.

    Returns:
        A list of supported IOC types.
    """
    return SUPPORTED_IOC_TYPES
