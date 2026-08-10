FROM python:3.12-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir uv && \
    uv sync --frozen --no-dev

RUN useradd --create-home --uid 10001 mailnuke && \
    mkdir -p /data && \
    chown -R mailnuke:mailnuke /data /app

USER mailnuke

ENV PATH="/app/.venv/bin:$PATH" \
    MAIL_NUKE_DATA_DIR=/data

EXPOSE 8765

CMD ["uvicorn", "mail_nuke.app:app", "--host", "0.0.0.0", "--port", "8765"]
