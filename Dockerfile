FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PORT=8000

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt \
    && python -m playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright

COPY app ./app
COPY static ./static

RUN useradd --create-home appuser
USER appuser

EXPOSE 8000
# exec so uvicorn becomes PID 1 and receives SIGTERM/SIGINT directly (clean Ctrl+C / docker stop).
# --proxy-headers: behind a host's load balancer (Render, Cloud Run) take the client IP from
# X-Forwarded-For so rate limits apply per real client. FORWARDED_ALLOW_IPS defaults to "*"
# because the container is only reachable through that proxy; set it to the proxy's range when known.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-*}\""]
