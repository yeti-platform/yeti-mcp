import pytest
import asyncio
import json
from unittest.mock import patch
from fastmcp import Client
from src import main


@pytest.mark.asyncio
@patch("src.main.tools.get_yeti_client")
async def test_match_observables(mock_yeti_client):
    mock_yeti_client.return_value.match_observables.return_value = {
        "result": "mocked_result"
    }
    async with Client(main.mcp) as client:
        result = await client.call_tool(
            "match_observables", {"observables": ["google.com"]}
        )
        assert json.loads(result[0].text) == {"result": "mocked_result"}
        mock_yeti_client.return_value.match_observables.assert_called_once_with(
            ["google.com"], regex_match=True
        )


@pytest.mark.asyncio
@patch("src.main.tools.get_yeti_client")
async def test_search_observables(mock_yeti_client):
    mock_yeti_client.return_value.search_observables.return_value = {
        "result": "mocked_search_result"
    }
    async with Client(main.mcp) as client:
        result = await client.call_tool(
            "search_observables", {"value": "example.com", "tags": ["tag1", "tag2"]}
        )
        assert json.loads(result[0].text) == {"result": "mocked_search_result"}
        mock_yeti_client.return_value.search_observables.assert_called_once_with(
            "example.com",
            tags=["tag1", "tag2"],
            count=100,
            page=0,
        )
