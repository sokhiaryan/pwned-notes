FROM python:3.11-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY readflag.c /tmp/readflag.c
RUN gcc -O2 -o /tmp/readflag /tmp/readflag.c

FROM python:3.11-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        libcairo2 libcurl4 libexpat1 libfontconfig1 libfreetype6 \
        libharfbuzz0b libicu72 libturbojpeg0 libwebp7 zlib1g \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --create-home --home-dir /app app

COPY flag.txt /flag.txt
RUN chmod 0400 /flag.txt && chown root:root /flag.txt

COPY --from=builder /tmp/readflag /readflag
RUN chmod 4111 /readflag

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY tools/html2pdf /app/tools/html2pdf
COPY app /app/app
COPY docker/healthcheck.sh /app/healthcheck.sh

RUN chmod +x /app/healthcheck.sh /app/tools/html2pdf \
    && mkdir -p /app/work \
    && chown -R app:app /app

USER app

ENV HTML2PDF_BIN=/app/tools/html2pdf \
    HTML2PDF_WORK_DIR=/app/work

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD /app/healthcheck.sh

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "90", "app.main:app"]
