FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Create data directory
RUN mkdir -p /app/data

EXPOSE 8484

# Gunicorn statt Flask Dev-Server:
# --workers 2     = 2 Worker-Prozesse (ausreichend für Single-User)
# --timeout 120   = 2 Min Timeout (AI-Requests können länger dauern)
# --access-logfile - = Zugriffs-Logs auf stdout (für Docker logs)
CMD ["gunicorn", "--bind", "0.0.0.0:8484", "--workers", "2", "--timeout", "120", "--access-logfile", "-", "--chdir", "/app/backend", "app:app"]
