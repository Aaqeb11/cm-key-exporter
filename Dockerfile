FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY exporter.py .

# Expose metrics port
EXPOSE 9123

CMD ["python", "-u", "exporter.py"]
