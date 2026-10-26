FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV PORT=3000
EXPOSE 3000

# Usamos gunicorn para producción (más estable que el servidor de Flask)
CMD ["gunicorn", "--bind", "0.0.0.0:3000", "app:app"]