FROM docker.io/python:3.12.7-alpine

RUN adduser --no-create-home --disabled-password appuser && \
    apk --no-cache --update add git

WORKDIR /app
EXPOSE 8080/tcp
ENV PYTHONUNBUFFERED=True

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade -r requirements.txt && \
    pip install --no-cache-dir --upgrade "certbot-dns-hetzner==1.0.3"

RUN mkdir -p /usr/lib/acme-server/etc/letsencrypt && \
    mkdir -p /usr/lib/acme-server/var/lib/letsencrypt && \
    chown -R appuser:appuser /usr/lib/acme-server
COPY --chown=appuser entrypoint.sh /


USER appuser

# strange error when a path is set here
ENV MAIL={} 
ENV CA_ENABLED=false


ENTRYPOINT ["sh", "/entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]

HEALTHCHECK --start-period=30s --interval=3m --timeout=1s \
  CMD wget --quiet --spider http://127.0.0.1:8080/acme/directory || exit 1

COPY app /app