from typing import Any

from fastmcp import FastMCP

from .utils import get_yeti_client

mcp = FastMCP(name="yeti-tools")


@mcp.tool()
def match_observables(observables: list[str], regex_match: bool = True) -> list:
    """
    Match observables against Yeti's database.

    This performs a more complex search than a simple substring match:

    * Searches for exact matches of the observables.
    * Searches for indicators that match the observables.
    * Searches Yeti bloom filters for known observables.
    * Returns entities and indicators that linked to known observables.

    Can also perform regex matching if the user needs fuzzy searching or is not
    sure about the exact observable format.

    Args:
        observables: A list of observables to search for.
        regex_match: If True, uses regex matching for values passed in observables.
            Can be dramatically slower than exact matching, so use with caution.
            Default is True.

    Returns:
        A list of observables found in Yeti.
    """
    client = get_yeti_client()
    results = client.match_observables(observables, regex_match=regex_match)
    return results


@mcp.tool()
def search_observables(
    value: str,
    tags: list[str] | None = None,
    count: int = 100,
    page: int = 0,
) -> list:
    """
    Search for observables in Yeti.

    Args:
        value: A substring to search for in observable values.
            If the value is empty, it returns all observables.
        tags: A list of tags to filter the observables by. Default is None (no filtering).
        count: The max number of results to return. Default is 100.
        page: The page number for pagination. Starts at 0.

    Returns:
        A list of observables matching the search query.
    """
    client = get_yeti_client()
    results = client.search_observables(value, tags=tags, count=count, page=page)
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
    client = get_yeti_client()
    results = client.add_observables_bulk(observables, tags=tags)
    return results


@mcp.tool()
def tag_object(
    yeti_object: dict[str, Any],
    tags: list[str],
) -> dict[str, Any]:
    """
    Tag an object in Yeti.

    Args:
        yeti_object: The Yeti object to tag. This should be a dictionary
            representing the object, typically obtained from another API call.
            It must contain 'id' and 'root_type' keys.
        tags: A list of tags to apply to the object.

    Returns:
        A dictionary confirming the tagging operation.
    """
    client = get_yeti_client()
    result = client.tag_object(yeti_object, tags)
    return result


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
        source: The source object as a dictionary. It should contain 'id' and 'root_type' keys.
        target: The target object as a dictionary. It should contain 'id' and 'root_type' keys.
        link_type: The type of link to create (default is "related").
        description: An optional description for the link.

    Returns:
        A dictionary containing the details of the created link.
    """
    client = get_yeti_client()
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
        entity_type: The type of malware to filter by. Default is None (all types).
        description: A substring to search for in malware descriptions. Default is None (no filtering).
        tags: A list of tags to filter the malware by. Default is None (no filtering).
        count: The max number of results to return. Default is 100.
        page: The page number for pagination. Starts at 0.

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

    client = get_yeti_client()
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
        indicator_type: The type of indicator to filter by. Default is None (all types).
        description: A substring to search for in indicator descriptions. Default is None (no filtering).
        tags: A list of tags to filter the indicators by. Default is None (no filtering).
        count: The max number of results to return. Default is 100.
        page: The page number for pagination. Starts at 0.

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

    client = get_yeti_client()
    results = client.search_indicators(**kwargs)
    return results


@mcp.tool()
def search_dfiq(
    name: str,
    dfiq_type: str | None = None,
    count: int = 100,
    page: int = 0,
) -> list[dict[str, Any]]:
    """
    Search for DFIQ objects in Yeti.

    * Valid DFIQ types are {"scenario", "facet", "question"}
    * The DFIQ graph goes Scenario -> (optional Facet) -> Question.
    * Questions contain approaches to answering the question.
    * Names are case-insensitive.

    Leave the name empty to return all DFIQ objects; this is particulary useful
    if the name of the existing DFIQobject is not known.

    Args:
        name: Return DFIQ objects matching this name (substring).
            If the name is empty, it may return all DFIQ objects (behavior depends on API).
        dfiq_type: The type of DFIQ object to filter by (e.g., "scenario"). Default is None (all types).
        count: The max number of results to return. Default is 100.
        page: The page number for pagination. Starts at 0.

    Returns:
        A list of DFIQ objects matching the criteria.
    """
    client = get_yeti_client()
    results = client.search_dfiq(name=name, dfiq_type=dfiq_type, count=count, page=page)
    return results


@mcp.tool()
def get_neighbors(
    source: str,
    target_types: list[str] | None = None,
    direction: str = "outbound",
    min_hops: int = 1,
    max_hops: int = 1,
    count: int = 10,
    page: int = 0,
) -> list:
    """
    Get neighbors of an object by searching the Yeti graph. This can be
    used to find related objects based on the source object.

    Examples:
      * Find TTPs related to a threat actor entity
      * Find Yara rules associated to a malware entity
      * Find questions associated to a DFIQ scenario (can be 1 or 2 hops away)
      * Find related DFIQ objects (facets and questions) for a given DFIQ scenario.

    Args:
        source: The <root_type>/ID notation of the source object for which to find neighbors;
          e.g. entities/1234, dfiq/999, observables/5678, indicators/888.
        direction: The direction of the search, either "inbound" or "outbound" or "any".
        target_types: A list of target object (entities or indicators) types to filter neighbors by. Default is None (all types).
        min_hops: The minimum number of hops to traverse in the graph. Default is 1.
        max_hops: The maximum number of hops to traverse in the graph. Default is 1.
        count: The max number of results to return. Default is 10.
        page: The page number for pagination. Starts at 0.

    Returns:
        A list of neighbors for the source object. The neighbors already contain all object data.
        If the number of results is lower than count, the last page has been reached.
    """
    client = get_yeti_client()
    if not target_types:
        target_types = []
    return client.search_graph(
        source,
        target_types=target_types,
        include_original=False,
        direction=direction,
        min_hops=min_hops,
        max_hops=max_hops,
        count=count,
        page=page,
    )
