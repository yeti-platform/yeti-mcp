import pytest
import asyncio
import json
from unittest.mock import patch
from fastmcp import Client
from src import main


@pytest.mark.asyncio
@patch("src.main.tools.get_yeti_client")
async def test_match_observables(mock_yeti_client):
    mock_yeti_client.return_value.match_observables.return_value = [
        {"result": "mocked_result"}
    ]
    async with Client(main.mcp) as client:
        result = await client.call_tool(
            "match_observables", {"observables": ["google.com"]}
        )
        assert result.data == [{"result": "mocked_result"}]
        mock_yeti_client.return_value.match_observables.assert_called_once_with(
            ["google.com"], regex_match=True
        )


@pytest.mark.asyncio
@patch("src.main.tools.get_yeti_client")
async def test_search_observables(mock_yeti_client):
    mock_yeti_client.return_value.search_observables.return_value = [
        {"result": "mocked_search_result"}
    ]
    async with Client(main.mcp) as client:
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
@patch("src.main.tools.get_yeti_client")
async def test_add_observables_bulk(mock_yeti_client):
    mock_yeti_client.return_value.add_observables_bulk.return_value = [
        {"type": "ip", "value": "1.2.3.4"}
    ]
    async with Client(main.mcp) as client:
        result = await client.call_tool(
            "add_observables_bulk",
            {"observables": [{"type": "ip", "value": "1.2.3.4"}], "tags": ["malware"]},
        )
        assert result.data == [{"type": "ip", "value": "1.2.3.4"}]
        mock_yeti_client.return_value.add_observables_bulk.assert_called_once_with(
            [{"type": "ip", "value": "1.2.3.4"}], tags=["malware"]
        )


@pytest.mark.asyncio
@patch("src.main.tools.get_yeti_client")
async def test_tag_object(mock_yeti_client):
    mock_yeti_client.return_value.tag_object.return_value = {"status": "ok"}
    yeti_object = {"id": "123", "root_type": "entity"}
    tags = ["tag1", "tag2"]
    async with Client(main.mcp) as client:
        result = await client.call_tool(
            "tag_object", {"yeti_object": yeti_object, "tags": tags}
        )
        assert result.data == {"status": "ok"}
        mock_yeti_client.return_value.tag_object.assert_called_once_with(
            yeti_object, tags
        )


@pytest.mark.asyncio
@patch("src.main.tools.get_yeti_client")
async def test_link_objects(mock_yeti_client):
    mock_yeti_client.return_value.link_objects.return_value = {"link": "created"}
    source = {"id": "1", "root_type": "observable"}
    target = {"id": "2", "root_type": "entity"}
    async with Client(main.mcp) as client:
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
@patch("src.main.tools.get_yeti_client")
async def test_search_entities(mock_yeti_client):
    mock_yeti_client.return_value.search_entities.return_value = [{"name": "entity1"}]
    async with Client(main.mcp) as client:
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
@patch("src.main.tools.get_yeti_client")
async def test_search_indicators(mock_yeti_client):
    mock_yeti_client.return_value.search_indicators.return_value = [
        {"name": "indicator1"}
    ]
    async with Client(main.mcp) as client:
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
@patch("src.main.tools.get_yeti_client")
async def test_search_dfiq(mock_yeti_client):
    mock_yeti_client.return_value.search_dfiq.return_value = [
        {"name": "scenario1"},
    ]
    async with Client(main.mcp) as client:
        result = await client.call_tool(
            "search_dfiq",
            {"name": "scenario1", "dfiq_type": "scenario", "count": 100, "page": 0},
        )
        assert result.data == [{"name": "scenario1"}]
        mock_yeti_client.return_value.search_dfiq.assert_called_once_with(
            name="scenario1", dfiq_type="scenario", count=100, page=0
        )


@pytest.mark.asyncio
@patch("src.main.tools.get_yeti_client")
async def test_get_neighbors(mock_yeti_client):
    mock_yeti_client.return_value.search_graph.return_value = [{"id": "neighbor1"}]
    async with Client(main.mcp) as client:
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
        assert result.data == [{"id": "neighbor1"}]
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
