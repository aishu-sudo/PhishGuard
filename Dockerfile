# Use official lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Prevent Python from writing pyc files to disk and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

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
COPY Backend/app /app/Backend/app
COPY Backend/init_db.py /app/Backend/init_db.py

# Copy Research models and dataset needed for prediction
COPY Research/models /app/Research/models
COPY Research/data /app/Research/data

# Set PYTHONPATH so python can locate app modules
ENV PYTHONPATH=/app/Backend

# Expose port
EXPOSE 8000

# Run uvicorn server binding to 0.0.0.0:$PORT
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
