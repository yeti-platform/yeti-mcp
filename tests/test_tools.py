import json
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import Client
from yeti.api import YetiApi

from src import server


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_match_observables(mock_yeti_client):
    # Shape of the POST /api/v2/graph/match response.
    match_response = {
        "entities": [],
        "observables": [],
        "known": [],
        "matches": [],
        "unknown": ["google.com"],
    }
    mock_yeti_client.return_value.match_observables.return_value = match_response
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "match_observables", {"observables": ["google.com"]}
        )
        assert result.data == match_response
        mock_yeti_client.return_value.match_observables.assert_called_once_with(
            ["google.com"], regex_match=True
        )


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_search_observables(mock_yeti_client):
    mock_yeti_client.return_value.search_observables.return_value = [
        {"result": "mocked_search_result"}
    ]
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "search_observables", {"value": "example.com", "tags": ["tag1", "tag2"]}
        )
        assert result.data == [{"result": "mocked_search_result"}]
        mock_yeti_client.return_value.search_observables.assert_called_once_with(
            "example.com",
            tags=["tag1", "tag2"],
            count=100,
            page=0,
        )


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_add_observables_bulk(mock_yeti_client):
    # Shape of the POST /api/v2/observables/bulk response.
    bulk_response = {"added": [{"type": "ipv4", "value": "1.2.3.4"}], "failed": []}
    mock_yeti_client.return_value.add_observables_bulk.return_value = bulk_response
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "add_observables_bulk",
            {"observables": [{"type": "ip", "value": "1.2.3.4"}], "tags": ["malware"]},
        )
        assert result.data == bulk_response
        mock_yeti_client.return_value.add_observables_bulk.assert_called_once_with(
            [{"type": "ip", "value": "1.2.3.4"}], tags=["malware"]
        )


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_tag_object(mock_yeti_client):
    mock_yeti_client.return_value.tag_object.return_value = {"status": "ok"}
    yeti_object = {"id": "123", "root_type": "entity"}
    tags = ["tag1", "tag2"]
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "tag_object", {"yeti_object": yeti_object, "tags": tags}
        )
        assert result.data == {"status": "ok"}
        mock_yeti_client.return_value.tag_object.assert_called_once_with(
            yeti_object, tags
        )


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_link_objects(mock_yeti_client):
    mock_yeti_client.return_value.link_objects.return_value = {"link": "created"}
    source = {"id": "1", "root_type": "observable"}
    target = {"id": "2", "root_type": "entity"}
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "link_objects",
            {
                "source": source,
                "target": target,
                "link_type": "related",
                "description": "used by",
            },
        )
        assert result.data == {"link": "created"}
        mock_yeti_client.return_value.link_objects.assert_called_once_with(
            source, target, "related", "used by"
        )


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_search_entities(mock_yeti_client):
    mock_yeti_client.return_value.search_entities.return_value = [{"name": "entity1"}]
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "search_entities",
            {
                "name": "entity1",
                "entity_type": "malware",
                "description": None,
                "tags": None,
            },
        )
        assert result.data == [{"name": "entity1"}]
        mock_yeti_client.return_value.search_entities.assert_called_once_with(
            name="entity1", count=100, page=0, entity_type="malware"
        )


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_get_multiple_entities(mock_yeti_client):
    mock_yeti_client.return_value.get_multiple_entities.return_value = [
        {"name": "entity1"},
        {"name": "entity2"},
    ]
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "get_multiple_entities",
            {
                "names": ["entity1", "entity2"],
                "count": 100,
                "page": 0,
            },
        )
        assert result.data == [{"name": "entity1"}, {"name": "entity2"}]
        mock_yeti_client.return_value.get_multiple_entities.assert_called_once_with(
            ["entity1", "entity2"], count=100, page=0
        )


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_search_indicators(mock_yeti_client):
    mock_yeti_client.return_value.search_indicators.return_value = [
        {"name": "indicator1"}
    ]
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "search_indicators",
            {
                "name": "indicator1",
                "indicator_type": "yara",
                "description": None,
                "tags": None,
            },
        )
        assert result.data == [{"name": "indicator1"}]
        mock_yeti_client.return_value.search_indicators.assert_called_once_with(
            name="indicator1", count=100, page=0, indicator_type="yara"
        )


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_get_multiple_indicators(mock_yeti_client):
    mock_yeti_client.return_value.get_multiple_indicators.return_value = [
        {"name": "indicator1"},
        {"name": "indicator2"},
    ]
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "get_multiple_indicators",
            {
                "names": ["indicator1", "indicator2"],
                "count": 100,
                "page": 0,
            },
        )
        assert result.data == [{"name": "indicator1"}, {"name": "indicator2"}]
        mock_yeti_client.return_value.get_multiple_indicators.assert_called_once_with(
            ["indicator1", "indicator2"], count=100, page=0
        )


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_search_dfiq(mock_yeti_client):
    mock_yeti_client.return_value.search_dfiq.return_value = [
        {"name": "scenario1"},
    ]
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "search_dfiq",
            {"name": "scenario1", "dfiq_type": "scenario", "count": 100, "page": 0},
        )
        assert result.data == [{"name": "scenario1"}]
        mock_yeti_client.return_value.search_dfiq.assert_called_once_with(
            name="scenario1", dfiq_type="scenario", count=100, page=0
        )


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_get_multiple_dfiq(mock_yeti_client):
    mock_yeti_client.return_value.get_multiple_dfiq.return_value = [
        {"name": "scenario1"},
        {"name": "scenario2"},
    ]
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "get_multiple_dfiq",
            {
                "names": ["scenario1", "scenario2"],
                "count": 100,
                "page": 0,
            },
        )
        assert result.data == [{"name": "scenario1"}, {"name": "scenario2"}]
        mock_yeti_client.return_value.get_multiple_dfiq.assert_called_once_with(
            ["scenario1", "scenario2"], count=100, page=0
        )


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_get_neighbors(mock_yeti_client):
    # Shape of the POST /api/v2/graph/search response.
    graph_response = {
        "vertices": {"entities/5678": {"id": "5678", "name": "neighbor1"}},
        "paths": [[{"source": "entities/1234", "target": "entities/5678"}]],
        "total": 1,
    }
    mock_yeti_client.return_value.search_graph.return_value = graph_response
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "get_neighbors",
            {
                "source": "entities/1234",
                "target_types": ["malware"],
                "direction": "outbound",
                "min_hops": 1,
                "max_hops": 2,
                "count": 5,
                "page": 0,
            },
        )
        assert result.data == graph_response
        mock_yeti_client.return_value.search_graph.assert_called_once_with(
            "entities/1234",
            target_types=["malware"],
            include_original=False,
            direction="outbound",
            min_hops=1,
            max_hops=2,
            count=5,
            page=0,
        )


def _real_client(response):
    """A real yeti-python client whose HTTP calls are mocked.

    Unlike a MagicMock, it fails if a tool passes arguments the client method
    doesn't take, and shows the request the client would send.
    """
    client = YetiApi("http://yeti")
    client.do_request = MagicMock(return_value=json.dumps(response))
    return client


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_link_objects_without_description(mock_yeti_client):
    # Yeti's POST /api/v2/graph/add requires a string description.
    client = _real_client({"id": "3"})
    mock_yeti_client.return_value = client
    async with Client(server.mcp) as mcp_client:
        await mcp_client.call_tool(
            "link_objects",
            {
                "source": {"id": "1", "root_type": "observable"},
                "target": {"id": "2", "root_type": "entity"},
            },
        )
    assert client.do_request.call_args.kwargs["json_data"]["description"] == ""


@pytest.mark.asyncio
@patch("src.yeti_mcp.tools.get_yeti_client")
async def test_search_entities_with_tags(mock_yeti_client):
    client = _real_client({"entities": [{"name": "Emotet"}], "total": 1})
    mock_yeti_client.return_value = client
    async with Client(server.mcp) as mcp_client:
        result = await mcp_client.call_tool(
            "search_entities", {"name": "Emotet", "tags": ["loader"]}
        )
    assert result.data == [{"name": "Emotet"}]
    assert client.do_request.call_args.kwargs["json_data"]["query"] == {
        "name": "Emotet",
        "tags": ["loader"],
    }
