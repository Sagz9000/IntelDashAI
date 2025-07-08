# Use a newer official Python runtime as a parent image (Debian Bookworm)
FROM python:3.10-slim-bookworm

# Set the working directory in the container
WORKDIR /app

# Install necessary build tools, sqlite3 development headers, and curl
# Also install python3-dev for compiling Python extensions
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libsqlite3-dev \
    python3-dev \
    curl && \
    rm -rf /var/lib/apt/lists/*

# Copy the requirements file first to leverage Docker's cache
COPY requirements.txt .

# Install pysqlite3-binary first to ensure it's available for chromadb and other dependencies
RUN pip install --no-cache-dir pysqlite3-binary \
    && pip install --no-cache-dir -r requirements.txt

# Set environment variable for ChromaDB to find the pysqlite3 extension
# This path is typical for pysqlite3-binary installations
ENV PYTHON_SQLITE_EXTENSION_MODULE=pysqlite3.dbapi2

# Copy the rest of the application code
COPY . /app

# Ensure the 'templates' directory exists and contains index.html
# Flask expects templates in a 'templates' subfolder by default
RUN mkdir -p /app/templates
COPY templates/index.html /app/templates/index.html

# Expose port 5000 (Flask default)
EXPOSE 5000

# Set Flask environment variables for AI service discovery
# Points to the Ollama service name in docker-compose
ENV FLASK_APP=app.py
ENV OLLAMA_BASE_URL=http://ollama:11434
# Points to the ChromaDB service name in docker-compose
ENV CHROMA_HOST=chromadb
ENV CHROMA_PORT=8000

# Run app.py when the container launches
CMD ["flask", "run", "--host=0.0.0.0"]
