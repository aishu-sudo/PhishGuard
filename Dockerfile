# Use official lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Prevent Python from writing pyc files to disk and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements
COPY Backend/requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt rapidfuzz pandas python-whois ipwhois mmh3

# Copy Backend codebase
COPY Backend /app/Backend

# Copy Research models and datasets
COPY Research /app/Research

# Set PYTHONPATH so python can locate app and Backend modules
ENV PYTHONPATH=/app/Backend:/app

# Expose port
EXPOSE 8000

# Run uvicorn server binding to 0.0.0.0:${PORT:-8000}
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
