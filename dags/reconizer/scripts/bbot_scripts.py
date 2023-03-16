"""
    This file contains all modules associated with bbot osint tool
"""

from bbot.scanner import scanner
from shodan import Shodan

from reconizer.scripts.bbot_helper import clean_scan_folder, \
    create_config_from_secrets, \
    filtered_events, get_scan_result


def bbot_raw_data_task(domain: str, secrets: dict):
    # duplicate code for now becuase there was another request for raw data
    config = create_config_from_secrets(secrets)
    shodan_object = Shodan(secrets.get("shodan_dns"))
    scan_name = "bbot_raw_data"
    sub_mods = ["censys", "wayback", "urlscan", "threatminer", "sublist3r", "pgp",
                "bucket_aws", "bucket_azure", "bucket_gcp"]
    scan = scanner.Scanner(domain, config=config, modules=sub_mods)
    res = []
    for event in scan.start():
        res.append(event.json())

    if scan.status == "FINISHED":
        # this is all the events in raw data
        # events = get_scan_result(filepath=f'{scan_name}/output.json', mode="json")
        return res
    else:
        return {}


def bbot_events_iteration(domain: str, secrets: dict):
    config = create_config_from_secrets(secrets)
    shodan_object = Shodan(secrets.get("shodan_dns"))
    scan_name = "bbot_filtered_data"
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
        # filter merge and group by events
        data = filtered_events(events, domain, shodan_object)
        # delete the report file
        clean_scan_folder(scan_name)
        return data
    else:
        return {}
