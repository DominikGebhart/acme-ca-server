FROM docker.io/python:3.12.7-alpine

RUN adduser --no-create-home --disabled-password appuser && \
    apk update --no-cache

WORKDIR /app
EXPOSE 8080/tcp
ENV PYTHONUNBUFFERED=True

COPY app /app
RUN pip install --no-cache-dir --upgrade -r requirements.txt
RUN mkdir -p /usr/lib/acme-server/etc/letsencrypt && \
    mkdir -p /usr/lib/acme-server/var/lib/letsencrypt && \
    chown -R appuser:appuser /usr/lib/acme-server
COPY --chown=appuser entrypoint.sh /

USER appuser

ENTRYPOINT ["sh", "/entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]

HEALTHCHECK --start-period=30s --interval=3m --timeout=1s \
  CMD wget --quiet --spider http://127.0.0.1:8080/acme/directory || exit 1
