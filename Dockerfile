# ==============================================================================
# SentinelLog — Hardened Non-Root Container Image
# ==============================================================================
FROM python:3.12-slim AS runtime

# Set security and performance environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

# Create non-root user and group (Principle of Least Privilege)
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -s /bin/bash -m sentinel

WORKDIR /app

# Install dependencies before copying source for optimal Docker layer caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY --chown=sentinel:sentinel main.py ./
COPY --chown=sentinel:sentinel sentinellog/ ./sentinellog/
COPY --chown=sentinel:sentinel reports/ ./reports/
COPY --chown=sentinel:sentinel logs/ ./logs/

# Switch to non-root user
USER sentinel

# Container healthcheck querying internal /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:' + str(__import__('os').getenv('PORT', 8000)) + '/health')" || exit 1

EXPOSE 8000

# Default command: launch SentinelLog web dashboard & API
CMD ["python", "main.py", "--web", "--port", "8000"]
