FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    CYBRWIRE_HOME=/data \
    CYBRWIRE_KEYCHAIN=off \
    CYBRWIRE_WEB_HOST=0.0.0.0 \
    CYBRWIRE_WEB_PORT=8000

WORKDIR /app
COPY pyproject.toml readme.md LICENSE ./
COPY cybrwire ./cybrwire
RUN pip install --no-cache-dir ".[web]" \
    && useradd --create-home --uid 1000 cybrwire \
    && mkdir /data && chown cybrwire /data

USER cybrwire
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=60s --timeout=5s --start-period=15s \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/login', timeout=4)" || exit 1
CMD ["cybrwire-web"]
