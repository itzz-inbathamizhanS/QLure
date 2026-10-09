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
EXPOSE 8080
# --proxy-headers: the real visitor IP comes from the gateway, and only the gateway is trusted.
CMD ["uvicorn", "decoys.web.app:app", "--host", "0.0.0.0", "--port", "8080", \
     "--no-server-header", "--proxy-headers", "--forwarded-allow-ips", "172.30.0.2", \
     "--limit-concurrency", "100", "--timeout-keep-alive", "5"]
