from typing import Tuple

from bbot.scanner.scanner import Scanner


def scan(domain: str) -> Tuple[list, list]:
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
