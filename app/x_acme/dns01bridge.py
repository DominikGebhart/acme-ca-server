import argparse
import copy
from typing import Optional, Tuple

import certbot
import certbot._internal.main as certbot_main
import certbot._internal.plugins.disco as certbot_disco
import certbot.configuration as certbot_configuration
import certbot.crypto_util as certbot_crypto_util
import certbot.util as certbot_util
import configobj
import josepy as jose
from acme import client as acme_client
from acme import errors as acme_errors
from acme import messages as acme_messages
from ca import model as ca_model
from certbot import configuration, crypto_util, errors, interfaces, util
from certbot._internal import (account, cert_manager, cli, client, constants,
                               eff, hooks, log, renewal, snap_config, storage,
                               updater)
from certbot._internal.display import obj as display_obj
from certbot._internal.display import util as internal_display_util
from certbot._internal.main import _init_le_client
from certbot._internal.plugins import disco as plugins_disco
from certbot._internal.plugins import selection as plug_sel
from certbot.compat import filesystem, misc, os
from certbot.display import ops as display_ops
from certbot.display import util as display_util
from certbot.plugins import enhancements
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from josepy import b64

import shlex
import datetime

#import logging
#logging.basicConfig()
#logging.getLogger().setLevel(logging.getLevelName(os.getenv("DNS01_LOG_LEVEL", 'INFO')))
from logger import logger

logger.setLevel(os.getenv("DNS01_LOG_LEVEL", 'INFO'))

# Most robust way to configure certbot turned out to be via its commandline arguments
# We set most configuration here and just add some real parameters via DNS01_CERTBOT_CLI_ARGS
params=["certonly", 

    "--cert-path=/tmp", # needed even if we don't save any
    "--chain-path=/tmp", # needed even if we don't save any
    "--fullchain-path=/tmp", # needed even if we don't save any
    #"--noninteractive",
    #"--dry-run",
    "--debug",
    "--config-dir=/tmp/etc/letsencrypt", # TODO: See if we can remove or move to persistent volume
    "--work-dir=/tmp/var/lib/letsencrypt", # TODO: See if we can remove or move to persistent volume
    "--logs-dir=/tmp/var/log/letsencrypt", # TODO: See if we can remove or move to persistent volume
    #"--server=https://acme-staging-v02.api.letsencrypt.org/directory",
    "--agree-tos",
    "--no-eff-email",
    "--register-unsafely-without-email"
    ]

certbot_cli_args_str = os.getenv("DNS01_CERTBOT_CLI_ARGS", None)

if certbot_cli_args_str is None:
    raise ValueError('DNS01_CERTBOT_CLI_ARGS not set')

certbot_cli_args_str_merged = f"{certbot_cli_args_str}\n{' '.join(params)}"
certbot_cli_args = shlex.split(certbot_cli_args_str_merged) 

logger.debug(f"Certbot cli arguments: {certbot_cli_args}")

def run_dns01_bridge(http01_x509_csr: x509.CertificateSigningRequest, subject_domain: str, san_domains: list[str]) -> ca_model.SignedCertInfo:

    

    c_pluginRegistry = certbot_disco.PluginsRegistry.find_all()
    c_NamespaceConfig = cli.prepare_and_parse_args(c_pluginRegistry, certbot_cli_args)

    # finalize namespace
    c_NamespaceConfig.csr = True
    c_NamespaceConfig.finalize_timeout_seconds = os.getenv("DNS01_FINALIZE_TIMEOUT_SECONDS", None)
    c_NamespaceConfig.set_argument_sources({})
    [setattr(c_NamespaceConfig, h + "_hook", None) for h in ("pre", "post", "renew", "manual_auth", "manual_cleanup")]
    
    # hand over csr from http01
    typ, csr, domains = certbot_crypto_util.import_csr_file(None, http01_x509_csr.public_bytes(Encoding.PEM))
    c_NamespaceConfig.actual_csr = (csr, typ)

    # FIXME: Check support for san domains

    # obtain_certificate_from_csr requires config.domains to be set    
    c_NamespaceConfig.domains = []
    for domain in domains:
        domain = certbot_util.enforce_domain_sanity(domain.strip())
        if domain not in c_NamespaceConfig.domains:
            c_NamespaceConfig.domains.append(domain)

    
    # init certbot logging
    with certbot_main.make_displayer(c_NamespaceConfig) as displayer:
        certbot_main.display_obj.set_display(displayer)
    
    # Run certbot DNS01
    try:
        cert_bytes, chain_bytes = run_dns01_certonly(config=c_NamespaceConfig, plugins=c_pluginRegistry)
        # return result in expected format
        cert = x509.load_pem_x509_certificate(cert_bytes, None)
        return ca_model.SignedCertInfo(cert, (cert_bytes + chain_bytes).decode("utf-8"))
    except Exception as e:
        logger.error(e)
    return

def run_dns01_certonly(config: configuration.NamespaceConfig, plugins: plugins_disco.PluginsRegistry) -> Tuple[
                           Optional[str], Optional[str], Optional[str], Optional[bytes], Optional[bytes]]:
    """Authenticate & obtain cert, but do not install it.

    This implements the 'certonly' subcommand.

    :param config: Configuration object
    :type config: configuration.NamespaceConfig

    :param plugins: List of plugins
    :type plugins: plugins_disco.PluginsRegistry

    :returns: `None`
    :rtype: None

    :raises errors.Error: If specified plugin could not be used

    """
    _, auth = plug_sel.choose_configurator_plugins(config, plugins, "certonly")
    
    le_client = _init_le_client(config, auth, None)
    if config.finalize_timeout_seconds:
        le_client.finalize_until_utc = datetime.datetime.utcnow() + datetime.timedelta(0, int(config.finalize_timeout_seconds))
        logger.info(f"Setting finalize timeout to {le_client.finalize_until_utc} (now + {config.finalize_timeout_seconds}s)")

    if not config.csr:        
        raise errors.ConfigurationError("Supports only csr mode")

    return _csr_get_and_save_cert(config, le_client)



def _csr_get_and_save_cert(config: configuration.NamespaceConfig,
                           le_client: client.Client) -> Tuple[
                           Optional[bytes], Optional[bytes]]:
    """Obtain a cert using a user-supplied CSR

    This works differently in the CSR case (for now) because we don't
    have the privkey, and therefore can't construct the files for a lineage.
    So we just save the cert & chain to disk :/

    :param config: Configuration object
    :type config: configuration.NamespaceConfig

    :param client: Client object
    :type client: client.Client

    :returns: `cert_path`, `chain_path` and `fullchain_path` as absolute
              paths to the actual files, or None for each if it's a dry-run.
    :rtype: `tuple` of `str`

    """
    csr, _ = config.actual_csr
    csr_names = crypto_util.get_names_from_req(csr.data)
    display_util.notify(
        "{action} for {domains}".format(
            action="Simulating a certificate request" if config.dry_run else
                    "Requesting a certificate",
            domains=internal_display_util.summarize_domain_list(csr_names)
        )
    )
    cert, chain = le_client.obtain_certificate_from_csr(csr)

    return cert, chain
