# yeti-mcp

[![Unit tests](https://github.com/yeti-platform/yeti-mcp/actions/workflows/unittests.yaml/badge.svg?branch=main)](https://github.com/yeti-platform/yeti-mcp/actions/workflows/unittests.yaml)

## How to run

```
docker compose up -d
```

Launch a bash shell in the container:

```
docker compose exec yeti-mcp /bin/bash
```

Launch the web server:

```
uv run python -m src.server --mcp-host 0.0.0.0 --mcp-port 8081
```
