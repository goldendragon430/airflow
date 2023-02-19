"""
    This file contains all modules associated with bbot osint tool
"""
import itertools
import json
from typing import List

from reconizer.scripts.bbot_helper import clean_scan_folder, cloud_buckets_entrypoint_internal, \
    emails_entrypoint_internal, \
    parse_cloud_buckets, run_bbot_module, run_scan_cli, subdomains_entrypoint_internal


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


def ips_from_events(events: List[dict]) -> list:
    ips_list = list()
    for event in events:
        if "ipv4" in event["tags"] or "ipv6" in event["tags"]:
            ips_list.append(event["resolved_hosts"])

    ips = list(itertools.chain.from_iterable(ips_list))
    return ips


def all_modules_bbot_cli_entrypoint(domain: str):
    with open("bbot_modules.json", "r") as file:
        mods = json.loads(file.read()).keys()
        events = run_scan_cli(domain=domain, bbot_modules=list(mods))

    ips = ips_from_events(events)
    buckets = parse_cloud_buckets(events)
    result = dict(ips=ips, buckets=buckets)
    name = "bbot_all_modules_scan"
    clean_scan_folder(name)
    return dict(error=None, response=result)
