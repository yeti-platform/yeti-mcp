# yeti-mcp

[![Unit tests](https://github.com/yeti-platform/yeti-mcp/actions/workflows/unittests.yaml/badge.svg?branch=main)](https://github.com/yeti-platform/yeti-mcp/actions/workflows/unittests.yaml)

## How to run

The server needs a Yeti endpoint and API key:

```
export YETI_ENDPOINT=http://localhost:8000
export YETI_API_KEY=<YOUR_API_KEY_HERE>
```

Use a key of a dedicated Yeti user without admin rights: whatever the key
allows, a client of this server can ask for.

### Tool profiles

`--profile` (or `YETI_MCP_PROFILE`) sets which tools are exposed:

| Profile | Tools |
| --- | --- |
| `read` (default) | search and lookup tools only |
| `contribute` | also `add_observables_bulk`, `create_entity`, `create_indicator`, `add_context`, `tag_object` and `link_objects`, which add data to Yeti |

No tool deletes data. Each tool carries MCP annotations (`readOnlyHint`,
`destructiveHint`), which clients can use to decide when to ask for
confirmation. `link_objects` is marked destructive because it overwrites the
description of an existing link with the same source, target and type.

### stdio (default)

The MCP client starts the server itself, for example:

```json
{
  "mcpServers": {
    "yeti": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/yeti-mcp", "python", "-m", "src.server"],
      "env": {
        "YETI_ENDPOINT": "http://localhost:8000",
        "YETI_API_KEY": "<YOUR_API_KEY_HERE>",
        "YETI_MCP_PROFILE": "read"
      }
    }
  }
}
```

### HTTP

`--transport http` serves streamable HTTP on `http://<host>:<port>/mcp/`
(`--transport sse` serves the legacy SSE transport on `/sse`). It listens on
127.0.0.1:8081 unless `--mcp-host` and `--mcp-port` say otherwise.

Set `YETI_MCP_AUTH_TOKEN` to require `Authorization: Bearer <token>` on every
request. The server refuses to listen on anything other than a loopback
address without it.

With Docker:

```
docker compose up -d
docker compose exec yeti-mcp /bin/bash
```

Then, in the container:

```
export YETI_MCP_AUTH_TOKEN=<A_LONG_RANDOM_STRING>
uv run python -m src.server --transport http --mcp-host 0.0.0.0 --mcp-port 8081
```
