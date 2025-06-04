# Dockerfile
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

RUN apt-get update && apt-get install -y \
    git \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install uv

# Copy project dependency files
ADD . /app
WORKDIR /app
RUN uv sync --all-groups

# Expose the port the MCP server runs on (default 8081)
ENV PYTHONPATH /app

# Command to run the application
# We use 0.0.0.0 for the host to make it accessible from outside the container
# CMD ["uv", "run", "python", "main.py", "--mcp-host", "0.0.0.0", "--mcp-port", "8081"]

# Keep the container running
CMD ["tail", "-f", "/dev/null"]
