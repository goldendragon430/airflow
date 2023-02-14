"""
    This file contains all modules associated with bbot osint tool
"""

from reconizer.scripts.bbot_helper import run_bbot_flag, run_bbot_module


def shodan_dns_entrypoint(domain: str, api_key: str) -> dict:
    config_str = f'modules.shodan.api_key={api_key}'
    return run_bbot_module(domain=domain, bbot_module="shodan_dns", api_config=config_str)


def ssl_cert_entrypoint(domain: str) -> dict:
    return run_bbot_module(domain=domain, bbot_module="sslcert")


def subdomains_flag_entrypoint(domain: str) -> dict:
    return run_bbot_flag(domain=domain, flag="subdomain-enum")


def cloud_enumeration_flag_entrypoint(domain: str) -> dict:
    return run_bbot_flag(domain=domain, flag="cloud-enum")
