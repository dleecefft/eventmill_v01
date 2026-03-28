# Event Mill Container Image
# Multi-stage build for minimal production image

FROM python:3.12-slim-bookworm as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY pyproject.toml .
COPY README.md .

# Install dependencies
RUN pip install --no-cache-dir build && \
    pip install --no-cache-dir .[all]

# Production stage
FROM python:3.12-slim-bookworm

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY framework/ ./framework/
COPY plugins/ ./plugins/
COPY docs/ ./docs/

# Create workspace directory
RUN mkdir -p /app/workspace/sessions /app/workspace/artifacts /app/workspace/logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV EVENTMILL_WORKSPACE=/app/workspace
ENV EVENTMILL_LOG_LEVEL=INFO

# Default command
CMD ["python", "-m", "framework.cli.shell"]
