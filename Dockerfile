# SKY-VAULT : Docker Container Specification
# Multi-stage / minimal air-gapped ready container

FROM python:3.11-slim

# Enforce clean environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PORT=5000

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt || \
    pip install --no-cache-dir flask cryptography PyWavelets Pillow numpy reedsolo PyMuPDF reportlab

# Copy application source code
COPY . .

# Expose application port
EXPOSE 5000

# Health check probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/status || exit 1

# Run SKY-VAULT application server
CMD ["python", "app.py"]
