FROM python:3.10-slim

WORKDIR /workspace

# Install build dependencies for postgres and scientific packages
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt /workspace/
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . /workspace/

# Expose port and set module path
ENV PYTHONPATH=/workspace
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
