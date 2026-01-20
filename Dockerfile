# SMSLY Shared Library
# This is a Python library package, not a service.
# This Dockerfile is for Railway deployment compatibility only.

FROM python:3.11-slim

WORKDIR /app

# Copy the library code
COPY smsly-core/ ./smsly-core/
COPY __init__.py ./

# Install the library
RUN pip install --no-cache-dir ./smsly-core

# This is a library - create a minimal health endpoint
RUN pip install --no-cache-dir fastapi uvicorn

# Create minimal health server
RUN echo 'from fastapi import FastAPI\napp = FastAPI()\n@app.get("/health")\ndef health(): return {"status":"healthy","type":"library"}' > server.py

EXPOSE 8000

# Run minimal health server
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
