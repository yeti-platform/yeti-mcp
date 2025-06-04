# yeti-mcp

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
uv run python main.py --mcp-host 0.0.0.0 --mcp-port 8081
```
