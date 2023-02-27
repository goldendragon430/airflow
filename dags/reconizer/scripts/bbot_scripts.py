"""
    This file contains all modules associated with bbot osint tool
"""
from typing import List

from bbot.scanner import scanner
from shodan import Shodan

from reconizer.scripts.bbot_helper import clean_scan_folder, \
    create_config_from_secrets, \
    filtered_events, get_scan_result


def raw_data_report(events: List[dict]) -> List[dict]:
    raw_data = []
    for record in events[1:]:
        raw_data.append({k: record[k] for k in ('type', 'data', 'resolved_hosts', 'tags', 'module') if k in record})

    return raw_data


def bbot_events_iteration(domain: str, secrets: dict):
    config = create_config_from_secrets(secrets)
    shodan_object = Shodan(secrets.get("shodan_dns"))
    scan_name = "subdomain_bbot_with_ports"
    sub_mods = ["censys", "wayback", "urlscan", "threatminer", "sublist3r", "pgp",
                "bucket_aws", "bucket_azure", "bucket_gcp"]
    scan = scanner.Scanner(domain, config=config, output_modules=["json"], modules=sub_mods,
                           name=scan_name,
                           force_start=True)
    for event in scan.start():
        continue

    if scan.status == "FINISHED":
        # this is all the events
        events = get_scan_result(filepath=f'{scan_name}/output.json', mode="json")

        # write only relevant columns
        # return raw_data_report(events)

        # filter merge and group by events
        data = filtered_events(events, domain, shodan_object)

        # delete the report file
        clean_scan_folder(scan_name)
        return data
    else:
        return {}
