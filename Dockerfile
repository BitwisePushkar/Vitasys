FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/apps

WORKDIR /app

COPY requirements.txt /app/
RUN apt-get update && apt-get install -y netcat-traditional && \
    pip install --upgrade pip && pip install -r requirements.txt && \
    rm -rf /var/lib/apt/lists/*

COPY . /app/
COPY .env .env

RUN mkdir -p /app/static /app/media && \
    chmod -R 755 /app/static /app/media

EXPOSE 8000

CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "medtrax.asgi:application"]