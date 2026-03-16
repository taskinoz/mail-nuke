FROM python:3.12-slim

WORKDIR /app

COPY . /app

RUN pip install uv && \
    uv pip install --system imapclient html2text joblib python-dotenv scikit-learn pandas

CMD ["python", "-m", "trainer.imap_worker"]