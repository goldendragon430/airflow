import itertools
import json
import os
import subprocess
import time
from collections import defaultdict
from typing import List

import pandas as pd

MAX_SCAN_TIME = 600


def add_api_key_to_config(config_str: str) -> list:
    return ["-c", config_str]


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


def parse_subdomain_result(events: list, domain: str):
    domains = defaultdict(list)
    subdomains = defaultdict(list)
    for event in events:
        if event.get("type", "") == "DNS_NAME":
            if "subdomain" in event["tags"] and domain in event["data"]:
                subdomains[event["data"]].append(event["resolved_hosts"])
            else:
                domains[event["data"]].append(event["resolved_hosts"])

    for k, v in subdomains.items():
        try:
            merged = list(itertools.chain.from_iterable(v))
            subdomains[k] = list(set(merged))
        except Exception as err:
            subdomains[k] = list(itertools.chain.from_iterable(v))

    return subdomains, domains


def parse_emails_result(events: list):
    emails = set()
    for event in events:
        if event.get("type", "") == "EMAIL_ADDRESS":
            emails.add(event["data"])
    return list(emails)


def parse_cloud_buckets(events: list) -> list:
    buckets_urls = []
    for event in events:
        if event.get("type", "") == "STORAGE_BUCKET":
            filtered = {"url": event["data"].get("url", ""), "hosts": event["resolved_hosts"], "tags": event["tags"]}
            buckets_urls.append(filtered)

    return buckets_urls


def create_config_from_secrets(secrets: dict):
    bbot_config = {}
    for key, value in secrets.items():
        if "key" in key or "pass" in key:
            continue
        bbot_config[key] = dict(api_key=value)

    # because aws secrets can't store nested json properly
    bbot_config["censys"] = dict(api_id=secrets["censys_key"], api_secret=secrets["censys_pass"])
    return dict(modules=bbot_config, output_dir=os.getcwd(), ignore_failed_deps=True)


def filtered_events(events: list, domain: str) -> dict:
    subdomains, domains = parse_subdomain_result(events, domain)
    findings = parse_findings(events)
    emails = parse_emails_result(events)
    open_ports = parse_open_ports(events)
    buckets = parse_cloud_buckets(events)

    ports = list(open_ports.keys())
    final = dict()

    for domain in subdomains.keys():
        is_port_open = set()
        for port in ports:
            if port in subdomains[domain]:
                for p in open_ports[port]:
                    is_port_open.add(p)

        final[domain] = dict(host=subdomains[domain], open_ports=list(is_port_open))

    return dict(domains=domains, subdomains=final, findings=findings, emails=emails, buckets=buckets)


def parse_open_ports(events: list):
    result = defaultdict(list)
    for event in events:
        if event.get("type", "") in ["OPEN_TCP_PORT", "PROTOCOL"]:
            ip, port = event["data"]["host"].split(":") if type(event["data"]) == dict else event["data"].split(":")
            value = [int(port)]
            result[ip].append(value)

    for k, v in result.items():
        result[k] = list(set(itertools.chain.from_iterable(v)))
    return result


def parse_findings(events: list):
    findings = list()
    for event in events:
        if event.get("type", "") == "FINDING":
            findings.append(event["data"])
    return findings
