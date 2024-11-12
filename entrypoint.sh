#!/bin/sh

echo -en "dns_hetzner_api_token = ${DSN01_HETZNER_API_TOKEN}\n" > /usr/lib/acme-server/hetzner.ini

exec "$@"