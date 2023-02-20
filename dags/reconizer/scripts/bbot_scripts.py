"""
    This file contains all modules associated with bbot osint tool
"""
import itertools
from typing import List

from reconizer.scripts.bbot_helper import clean_scan_folder, cloud_buckets_entrypoint_internal, \
    emails_entrypoint_internal, \
    get_scan_result, parse_cloud_buckets, parse_emails_result, run_bbot_module, run_scan_cli, \
    subdomains_entrypoint_internal


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


def bbot_cli_entrypoint(domain: str):
    bbot_modules = ["threatminer", "bucket_aws", "bucket_azure", "bucket_gcp", "bypass403", "httpx", "wappalyzer",
                    "emailformat", "pgp", "skymem"]
    try:
        err, out = run_scan_cli(domain=domain, bbot_modules=bbot_modules)
        scan_folder = "bbot_all_modules_scan"
        scan_result_file = f'{scan_folder}/output.json'
        events = get_scan_result(filepath=scan_result_file, mode="json")
        print("got events")
        ips = ips_from_events(events)
        buckets = parse_cloud_buckets(events)
        emails = parse_emails_result(events)
        result = dict(ips=ips, buckets=buckets, emails=emails, events=events)
        clean_scan_folder(scan_folder)
        print("return valid answer")
        return dict(error=None, response=result)
    except Exception as err:
        print(f'Error reading {domain}')
        return dict(error=str(err), response=None)
