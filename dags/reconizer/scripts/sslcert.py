import json
import os
import subprocess

from bbot.scanner.scanner import Scanner
from reconizer.services.user_defined_exceptions import PartiallyDataError


def ssl_cert_entrypoint_internal(domain: str):
    status = run_scan(domain)
    try:
        result = extract_after_status(status)
        output = dict(error=None, response=result)
    except Exception as err:
        output = dict(error=err, response=None)
    finally:
        subprocess.run(["rm", "-r", "ssl_cert_scan"], timeout=5, check=True)
    return output


def extract_after_status(status: str) -> list:
    if status == "FINISHED":
        events = []
        with open("ssl_cert_scan/output.json", mode="r") as file:
            for line in file:
                events.append(json.loads(line))

        list_of_keys = ["type", "data", "resolved_hosts", "module"]
        return [dict(map(lambda key: (key, event.get(key, None)), list_of_keys)) for event in events]

    raise PartiallyDataError("test")


def run_scan(domain: str):
    config = dict(output_dir=os.getcwd())
    scan = Scanner(domain, modules=["sslcert"], output_modules=["json"], name="ssl_cert_scan", config=config)
    for event in scan.start():
        print(event)
    return scan.status
