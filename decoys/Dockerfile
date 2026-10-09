# One image for every decoy. Each compose service picks its own command.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 QLURE_LOG_DIR=/var/log/qlure
WORKDIR /app

COPY pyproject.toml README.md ./
COPY qlure ./qlure
COPY decoys ./decoys
RUN pip install --no-cache-dir '.[decoys]' \
 && useradd --system --uid 10001 decoy \
 && mkdir -p /var/log/qlure && chown decoy /var/log/qlure

USER decoy
