FROM oven/bun:1 AS bun
FROM python:3.12-slim

WORKDIR /app

COPY . /app
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun

RUN pip install uv && \
    uv pip install --system imapclient html2text joblib python-dotenv scikit-learn pandas

CMD ["python", "-m", "trainer.imap_worker"]
