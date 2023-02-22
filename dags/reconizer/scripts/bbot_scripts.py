"""
    This file contains all modules associated with bbot osint tool
"""
import itertools
import os
from typing import List

import yaml
from bbot.scanner import scanner
from yaml.loader import SafeLoader

from reconizer.scripts.bbot_helper import clean_scan_folder, cloud_buckets_entrypoint_internal, \
    create_config_from_secrets, emails_entrypoint_internal, \
    filtered_events, get_scan_result, parse_cloud_buckets, parse_emails_result, run_bbot_module, run_scan_cli, \
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


def read_bbot_modules_yaml():
    filepath = os.path.join(os.getcwd(), "dags/reconizer/scripts/bbot.yaml")
    with open(filepath) as file:
        mods = yaml.load(file, Loader=SafeLoader)
        return list(mods["modules"].keys())


def bbot_events_iteration(domain: str, secrets: dict, start: int, end: int):
    config = create_config_from_secrets(secrets)
    scan_name = f'bbot_scan_general_{start}_{end}'
    bbot_mods = read_bbot_modules_yaml()
    mods = bbot_mods[start: min(len(bbot_mods), end)]
    scan = scanner.Scanner(domain, config=config, output_modules=["json"], modules=mods,
                           name=scan_name,
                           force_start=True)
    for event in scan.start():
        print(event)

    if scan.status == "FINISHED":
        events = get_scan_result(filepath=f'{scan_name}/output.json', mode="json")

        # don't write raw data to S3 for now
        raw_data = []
        for record in events[1:]:
            raw_data.append({k: record[k] for k in ('type', 'data', 'resolved_hosts', 'tags', 'module') if k in record})

        # filter and group by event type
        grouped_by = filtered_events(events)
        clean_scan_folder(scan_name)
        return grouped_by
    else:
        return {}
