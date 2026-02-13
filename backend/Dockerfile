FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# INTENTIONALLY INSECURE: Running as root, debug mode enabled
# TODO: Create non-root user, disable debug mode
CMD ["python", "app.py"]
