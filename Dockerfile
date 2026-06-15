FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY backend/ ./backend/
COPY frontend/ ./frontend/

RUN mkdir -p /app/data

EXPOSE 8484

CMD ["gunicorn", "--bind", "0.0.0.0:8484", "--workers", "2", "--timeout", "120", "--access-logfile", "-", "--chdir", "/app/backend", "app:app"]
