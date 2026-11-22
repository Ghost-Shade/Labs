FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install Python deps + Chromium in one layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium

# Copy app code
COPY . .

ENV DATA_DIR=/app/data
RUN mkdir -p /app/data

EXPOSE 5000
CMD ["python", "app.py"]