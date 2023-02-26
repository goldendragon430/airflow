"""
    This file contains all modules associated with bbot osint tool
"""

from bbot.scanner import scanner

from reconizer.scripts.bbot_helper import clean_scan_folder, \
    create_config_from_secrets, \
    filtered_events, get_scan_result, parse_cloud_buckets, parse_emails_result, run_scan_cli


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


def bbot_events_iteration(domain: str, secrets: dict):
    config = create_config_from_secrets(secrets)
    scan_name = "subdomain_bbot_with_ports"
    sub_mods = ["censys", "wayback", "urlscan", "threatminer", "sublist3r", "pgp",
                "bucket_aws", "bucket_azure", "bucket_gcp"]
    scan = scanner.Scanner(domain, config=config, output_modules=["json"], modules=sub_mods,
                           name=scan_name,
                           force_start=True)
    for event in scan.start():
        continue

    if scan.status == "FINISHED":
        events = get_scan_result(filepath=f'{scan_name}/output.json', mode="json")
        data = filtered_events(events, domain)
        clean_scan_folder(scan_name)
        return data
    else:
        return {}
