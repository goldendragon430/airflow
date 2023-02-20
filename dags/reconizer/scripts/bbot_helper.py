import json
import os
import subprocess
import time
from typing import List

import pandas as pd
from bbot.scanner.scanner import Scanner

from reconizer.services.user_defined_exceptions import PartiallyDataError

MAX_SCAN_TIME = 600


def add_api_key_to_config(config_str: str) -> list:
    return ["-c", config_str]


def run_scan(domain, **kwargs):
    dict_args = dict(config=dict(output_dir=os.getcwd()), name=f'{kwargs["modules"][0]}_scan')
    kwargs.update(dict_args)
    scan = Scanner(domain, **kwargs)
    for event in scan.start():
        print(event)

    if scan.status == "FINISHED":
        result = get_scan_result(**kwargs)
        # clean scan folder
        subprocess.run(["rm", "-r", kwargs["name"]], timeout=30, check=True)
        return result

    raise PartiallyDataError("test")


def get_scan_result(filepath: str, mode: str):
    path = os.path.join(os.getcwd(), filepath)
    if mode == "json":
        events = []
        with open(path, mode="r") as file:
            for line in file:
                events.append(json.loads(line))
        return events
    elif mode == "csv":
        return pd.read_csv(path)


def run_scan_cli(domain: str, bbot_modules: List[str], api_config: str = None):
    output_format = "json"
    name = "bbot_all_modules_scan"
    base_command = ["bbot", "-t", domain, "-m"]
    format_command = ["-o", os.getcwd(), "-n", name, "-y", "--ignore-failed-deps", "-om", output_format]
    if api_config:
        base_command += add_api_key_to_config(api_config)
    try:
        bbot_command = base_command + bbot_modules + format_command
        print(bbot_command)
        result = subprocess.run(bbot_command, capture_output=True)
    except Exception as err:
        return str(err)
    else:
        time.sleep(60)
        return result.stderr.decode("utf-8"), result.stdout.decode("utf-8")


def clean_scan_folder(scan_folder: str) -> None:
    path = os.path.join(os.getcwd(), scan_folder)
    try:
        subprocess.run(["rm", "-r", path], timeout=5, check=True)
    except subprocess.CalledProcessError as err:
        pass
    except OSError as err:
        pass


def run_bbot_module(domain: str, bbot_module: str, api_config: str = None) -> dict:
    scan_succeeded, output = run_scan_cli(domain=domain, bbot_module=bbot_module, api_config=api_config)
    if scan_succeeded:
        report = get_scan_result(filepath=output, mode="json")
        clean_scan_folder(scan_folder=f'{bbot_module}_scan')
        return dict(error=None, response=report)
    else:
        return dict(error=output, response=None)


def flag_cli_run(domain: str, flag: str, output_format: str = "json"):
    split_dash = flag.replace('-', '_')
    name = f'{split_dash}_scan'
    command = f'bbot -t {domain} -f {flag} -n {name} -o .  -y --ignore-failed-deps -om {output_format}'
    # currently limited scan time to 10 minutes
    result = subprocess.run(command.split(), capture_output=True, timeout=MAX_SCAN_TIME, text=True)
    return result.stdout


def run_bbot_flag(domain: str, flag: str) -> dict:
    scan_status = flag_cli_run(domain=domain, flag=flag, output_format="json")
    if os.path.isdir(f'{flag}_scan'):
        report = get_scan_result(filepath=f'{flag}_scan/output.csv', mode="json")
        # clean_scan_folder(scan_folder=f'{flag}_scan')
        return dict(error=None, response=report)
    else:
        return dict(error=f'status code {scan_status} please check your flags', response=None)


def run_bbot_vulnerability_modules(domain: str) -> dict:
    config = dict(output_dir=os.getcwd())
    vuln_modules = ["badsecrets", "generic_ssrf", "iis_shortnames", "telerik", "url_manipulation"]
    scan_name = "vuln_scan"
    scan = Scanner(domain, config=config, output_modules=["json"], modules=vuln_modules, name=scan_name,
                   force_start=True)
    for event in scan.start():
        print(event)

    if scan.status == "FINISHED":
        events = get_scan_result(f'{scan_name}/output.json', mode="json")

    return {}


def parse_subdomain_result(events: list):
    result = set()
    for event in events:
        if "subdomain" in event["tags"]:
            result.add(event["data"])

    return list(result)


def subdomains_entrypoint_internal(domain):
    config = dict(output_dir=os.getcwd())
    output_modules = "certspotter otx leakix ipneighbor hackertarget dnsdumpster dnscommonsrv crt crobat anubisdb " \
                     "dnszonetransfer wayback azure_tenant urlscan threatminer sublist3r riddler rapiddns"
    mods = output_modules.split()
    scan_name = "subdomains_scan"
    scan = Scanner(domain, config=config, output_modules=["json"], modules=mods, name=scan_name,
                   force_start=True)
    for event in scan.start():
        print(event)

    print("scan finished cool")
    if scan.status == "FINISHED":
        events = get_scan_result(f'{scan_name}/output.json', mode="json")
        print("got events correct")
        domains = parse_subdomain_result(events)
        print("got domains")
        result = {"error": None, "response": domains}
        print(json.dumps(result))
        clean_scan_folder(scan_name)
        return result

    result = {"error": "found no domains", "response": None}
    print(json.dumps(result))
    return result


def parse_emails_result(events: list) -> list:
    emails = set()
    for event in events:
        if event.get("type", "") == "EMAIL_ADDRESS":
            emails.add(event["data"])
    return list(emails)


def emails_entrypoint_internal(domain: str) -> dict:
    email_modules = "speculate emailformat pgp skymem PTR".split()
    config = dict(output_dir=os.getcwd())
    scan_name = "emails_scan"
    scan = Scanner(domain, config=config, output_modules=["json"], modules=email_modules, name=scan_name,
                   force_start=True)
    for event in scan.start():
        print(event)

    print("scan finished cool")
    if scan.status == "FINISHED":
        events = get_scan_result(f'{scan_name}/output.json', mode="json")
        print("got events correct")
        emails = parse_emails_result(events)
        print("got emails")
        result = {"error": None, "response": emails}
        print(json.dumps(result))
        clean_scan_folder(scan_name)
        return result

    result = {"error": "found no emails", "response": []}
    print(json.dumps(result))
    return result


def parse_cloud_buckets(events: list) -> list:
    buckets_urls = []
    for event in events:
        if event.get("type", "") == "STORAGE_BUCKET":
            filtered = {"url": event["data"].get("url", ""), "hosts": event["resolved_hosts"], "tags": event["tags"]}
            buckets_urls.append(filtered)

    return buckets_urls


def cloud_buckets_entrypoint_internal(domain: str) -> dict:
    config = dict(output_dir=os.getcwd())
    cloud_bucket_module = "bucket_aws bucket_azure bucket_digitalocean bucket_gcp".split()
    scan_name = "buckets_scan"
    scan = Scanner(domain, config=config, output_modules=["json"], modules=cloud_bucket_module, name=scan_name,
                   force_start=True)
    for event in scan.start():
        print(event)

    print("scan finished")
    if scan.status == "FINISHED":
        events = get_scan_result(f'{scan_name}/output.json', mode="json")
        print("got events correct")
        buckets = parse_cloud_buckets(events)
        print("got buckets urls")
        result = {"error": None, "response": buckets}
        print(json.dumps(result))
        clean_scan_folder(scan_name)
        return result

    result = {"error": "found no buckets", "response": []}
    print(json.dumps(result))
    return result


def read_modules(filepath: str) -> list:
    with open(filepath, mode="r") as file:
        mods = json.loads(file.read())
        return list(mods.keys())


def run_all_modules(domain: str) -> list:
    config = dict(output_dir=os.getcwd(), ignore_failed_deps=True)
    scan_name = "all_modules"
    bbot_modules = read_modules("bbot_modules.json")
    scan = Scanner(domain, config=config, output_modules=["json"], modules=bbot_modules, name=scan_name,
                   force_start=True)
    for event in scan.start():
        print(event)

    if scan.status == "FINISHED":
        events = get_scan_result(f'{scan_name}/output.json', mode="json")
        clean_scan_folder(scan_name)
        return events
    else:
        return []
