"""
    This file contains all modules associated with bbot osint tool
"""
import itertools

from reconizer.scripts.bbot_helper import cloud_buckets_entrypoint_internal, emails_entrypoint_internal, \
    run_all_modules, run_bbot_module, subdomains_entrypoint_internal


def shodan_dns_entrypoint(domain: str, api_key: str) -> dict:
    config_str = f'modules.shodan.api_key={api_key}'
    return run_bbot_module(domain=domain, bbot_module="shodan_dns", api_config=config_str)


def ssl_cert_entrypoint(domain: str) -> dict:
    return run_bbot_module(domain=domain, bbot_module="sslcert")


def subdomains_flag_entrypoint(domain: str) -> dict:
    return subdomains_entrypoint_internal(domain)


def emails_entrypoint(domain: str) -> dict:
    return emails_entrypoint_internal(domain)


def cloud_buckets_entrypoint(domain: str) -> dict:
    return cloud_buckets_entrypoint_internal(domain=domain)


def ips_entrypoint(domain: str) -> dict:
    events = run_all_modules(domain)

    ips_list = list()
    for event in events:
        if "ipv4" in event["tags"] or "ipv6" in event["tags"]:
            ips_list.append(event["resolved_hosts"])

    ips = list(itertools.chain.from_iterable(ips_list))
    return dict(error=None, response=ips)
