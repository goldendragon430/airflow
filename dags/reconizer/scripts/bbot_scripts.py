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


def read_bbot_modules_yaml():
    filepath = os.path.join(os.getcwd(), "dags/reconizer/scripts/bbot.yaml")
    with open(filepath) as file:
        mods = yaml.load(file, Loader=SafeLoader)
        return list(mods["modules"].keys())


def bbot_events_from_all_modules(domain: str, secrets: dict):
    config = create_config_from_secrets(secrets)
    scan_name = "bbot_scan_general"
    bbot_mods = read_bbot_modules_yaml()
    scan = scanner.Scanner(domain, config=config, output_modules=["json"], modules=bbot_mods, name=scan_name,
                           force_start=True)
    try:
        for event in scan.start():
            print(event)
    except Exception as err:
        print(err)
        pass
    finally:
        return scan.status


secrets = {"apollo": "z9tV-4JdDnurSiFrTBItMA", "app_brain": "p24594.0rke2dkkh9ec0rn2mo76d",
           "google": "AIzaSyA4AFdjloj5QVh1FvtE_Th-ayONGZKs22w", "haveibeenpawned": "42806857f18943debadc4156ea892c44",
           "mx": "66675eb1-cd13-493f-824e-a77f039cb53e", "rocketreach": "7fc8e4kc711fe050dccc9c83883a53edd280e64",
           "shodan_dns": "slf8J3ML9slEOmuBahHYhudCgD73rVgb", "signal": "202..nc7AFDvB1kibYsFI0jUuyHwDKcy",
           "spyse": "80f45c86-7a17-4c1e-8968-a5d885b9a3d5", "view_dns": "483a6a44a649e4f95821147da90a130ea44ad1c1",
           "wp_scan": "0aKpORSMkvP60g34PWXAWk4Ev7iWma4bLkyDvubu8q8",
           "censys_key": "bc3e9cbd-a04d-4ce8-afda-7c15e64d56f0", "censys_pass": "MNh6gcijt5jiynXi32LJQ1MDrMzU1Vwg",
           "xforce_key": "eefc9616-7f87-4290-9965-7ce53e22bbd3", "xforce_pass": "4be25c9c-ffa3-40e3-8a9c-017ba332466a"}

status = bbot_events_from_all_modules(domain="northmill.com", secrets=secrets)
if status == "FINISHED":
    d = get_scan_result("bbot_scan_general/output.json", mode="json")
    t = 1


def process_events(domain: str) -> List[dict]:
    events = get_scan_result("bbot_scan_general/output.json", mode="json")
    return events
