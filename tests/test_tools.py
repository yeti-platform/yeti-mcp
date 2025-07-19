import unittest
from unittest.mock import patch, MagicMock

from fastmcp import Client
from src import main

import asyncio
import json


class TestServerTools(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mcp_server = main.mcp

    @patch("src.main.tools.get_yeti_client")
    async def test_match_observables(self, mock_yeti_client):
        # Mock the response of match_observables
        async with Client(self.mcp_server) as client:
            mock_yeti_client.return_value.match_observables.return_value = {
                "result": "mocked_result"
            }
            result = await client.call_tool(
                "match_observables", {"observables": ["google.com"]}
            )
            self.assertEqual(json.loads(result[0].text), {"result": "mocked_result"})

            mock_yeti_client.return_value.match_observables.assert_called_once_with(
                ["google.com"], regex_match=True
            )

    @patch("src.main.tools.get_yeti_client")
    async def test_search_observables(self, mock_yeti_client):
        # Mock the response of search_observables
        async with Client(self.mcp_server) as client:
            mock_yeti_client.return_value.search_observables.return_value = {
                "result": "mocked_search_result"
            }
            result = await client.call_tool(
                "search_observables", {"value": "example.com", "tags": ["tag1", "tag2"]}
            )
            self.assertEqual(
                json.loads(result[0].text), {"result": "mocked_search_result"}
            )

            mock_yeti_client.return_value.search_observables.assert_called_once_with(
                "example.com",
                tags=["tag1", "tag2"],
                count=100,
                page=0,
            )
