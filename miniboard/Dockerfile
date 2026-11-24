# Use a valid Playwright Python image (v1.64.1-noble is confirmed to exist)
FROM mcr.microsoft.com/playwright/python:v1.64.1-noble

WORKDIR /app

# Install the Python packages. The Playwright wheel is still ~38 MB,
# so keep the long timeout to survive a slow connection.
COPY requirements.txt .
COPY wheels/ /wheels/

RUN pip install --no-index --find-links=/wheels -r requirements.txt

# Copy app code
COPY . .

ENV DATA_DIR=/app/data
RUN mkdir -p /app/data

EXPOSE 5000
CMD ["python", "app.py"]