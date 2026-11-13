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
CMD ["cybrwire-web"]
