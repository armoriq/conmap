# Use Python 3.13 slim image
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install system dependencies and uv
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/* \
    && curl -LsSf https://astral.sh/uv/install.sh | sh

# Add uv to PATH
ENV PATH="/root/.cargo/bin:$PATH"

# Copy dependency files
COPY pyproject.toml README.md ./

# Copy source code (needed for setuptools_scm version detection)
COPY src ./src

# Install dependencies (production only, no dev dependencies)
RUN uv pip install --system --no-cache .

# Copy remaining application code
COPY . .

# Expose port 8080 (Cloud Run default)
EXPOSE 8080

# Set environment variables for production
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

# Health check (optional but recommended for Cloud Run)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the Conmap API server
CMD ["conmap", "api", "--host", "0.0.0.0", "--port", "8080"]