# Multi-stage Docker build for QGuardian Security System
FROM python:3.9-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies with security updates
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    build-essential \
    curl \
    git \
    libmagic1 \
    libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies with security
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    pip cache purge

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash qguardian && \
    chown -R qguardian:qguardian /app
USER qguardian

# Expose ports
EXPOSE 8501 8080

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Default command
CMD ["python", "main_integration.py"]

# Development stage
FROM base as development

# Install development dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-asyncio \
    black \
    flake8 \
    mypy

# Set development environment
ENV ENVIRONMENT=development
ENV DEBUG=true

# Development command
CMD ["python", "-m", "pytest", "tests/", "-v"]

# Production stage
FROM base as production

# Set production environment
ENV ENVIRONMENT=production
ENV DEBUG=false

# Copy production configuration
COPY config.json.prod config.json

# Production command
CMD ["python", "main_integration.py"]

# Kubernetes stage
FROM base as kubernetes

# Install Kubernetes dependencies
RUN pip install --no-cache-dir kubernetes

# Copy Kubernetes configurations
COPY k8s/ /app/k8s/

# Kubernetes command
CMD ["python", "main_integration.py", "--kubernetes"] 