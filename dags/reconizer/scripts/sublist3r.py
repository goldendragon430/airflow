from typing import Tuple
from bbot.scanner.scanner import Scanner
import requests

from dags.services.ec2_kali_connect import run_command_on_remote_kali

def scan(domain: str) -> Tuple[list,list]:
    scan_results = []
    scan_errors = []
    scan = Scanner(domain, modules=["sublist3r"], output_modules=["json"])
    try:
        for event in scan.start():
            scan_results.append(event)
    except Exception as err:
        scan_errors.append(err)
    return scan_errors, scan_results


def sublist3r_entrypoint(domain: str) -> dict:
    scan_errors, scan_results = scan(domain)
    return dict(error=scan_errors, response=scan_results)


# bbot is more intensive if you just want to run sublist3r simple and fast use sublist3r_entrypoint_light
def sublist3r_entrypoint_light(domain: str) -> dict:
    secret_name= "prod/ec2_kali/ssh"
    command = f'sublist3r -d {domain}'
    std_out, std_err = run_command_on_remote_kali(command, secret_name)
    return dict(error=std_err, response=std_out)
