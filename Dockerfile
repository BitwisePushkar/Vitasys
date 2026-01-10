FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

COPY pyproject.toml uv.lock /app/
RUN uv sync --frozen --no-install-project

COPY . /app/

WORKDIR /app/Vitasys

RUN mkdir -p /app/Vitasys/static /app/Vitasys/media && \
    chmod -R 755 /app/Vitasys/static /app/Vitasys/media

EXPOSE 8000

CMD ["uv", "run", "daphne", "-b", "0.0.0.0", "-p", "8000", "Vitasys.asgi:application"]