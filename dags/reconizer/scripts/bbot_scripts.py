"""
    This file contains all modules that would run on Airflow environment without ssh and other connections
"""
import json
from reconizer.services.bbot_handler import BbotWrapper
from reconizer.services.services import get_secret
from reconizer.services.report_extractor import ReportExtractor
from reconizer.scripts.sslcert import ssl_cert_entrypoint_internal


def general_bbot_entrypoint(domain: str, module_name: str, api_key: str) -> tuple[list, list]:
    bbot_wrapper = BbotWrapper(domain)
    scan_status = bbot_wrapper.run_scan_python(module_name, api_key)
    scan_errors, scan_results = bbot_wrapper.check_scan_output(scan_status)
    return scan_errors, scan_results


def shodan_dns_entrypoint(domain: str, api_key: str) -> tuple[list, list]:
    return general_bbot_entrypoint(domain, "shodan_dns", api_key)


def ssl_cert_entrypoint(domain: str) -> dict:
    return ssl_cert_entrypoint_internal(domain)
