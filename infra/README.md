Needs:
```sh
EXTERNAL_DOMAIN_LIVE=live.acme.example.com
EXTERNAL_DOMAIN_STAGING=staging.acme.example.com
DNS01_HETZNER_API_TOKEN=XXXX
CADDY_CA_URL=https://acme-staging-v02.api.letsencrypt.org/directory
#CADDY_CA_URL=https://acme-v02.api.letsencrypt.org/directory
```

* live set to use letsencrypt staging url to be safe, switch when setup validated
* incoming acme http01 register account requests need to have a contact e-mail set
