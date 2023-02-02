"""
    This file contains all modules that would run on Airflow environment without ssh and other connections
"""
import json
from reconizer.services.bbot_handler import BbotWrapper
from reconizer.services.services import get_secret
import pandas as pd
from reconizer.services.report_extractor import ReportExtractor
import os


def general_bbot_entrypoint(domain: str, module_name: str, api_key: str) -> tuple[list, list]:
    bbot_wrapper = BbotWrapper(domain)
    scan_status = bbot_wrapper.run_scan_python(module_name, api_key)
    scan_errors, scan_results = bbot_wrapper.check_scan_output(scan_status)
    return scan_errors, scan_results


def shodan_dns_entrypoint(domain: str, api_key: str) -> tuple[list, list]:
    return general_bbot_entrypoint(domain, "shodan_dns", api_key)


secrets = get_secret("airflow/variables/secrets")
bbot_wrapper = BbotWrapper("www.toysrus.com", json.loads(secrets))
modules_names = ["httpx", "shodan_dns", "sslcert", "crt", "azure_tenant", "censys", "dnscommonsrv",
                 "bucket_digitalocean", "bypass403"]
scan_status = bbot_wrapper.run_scan_python(modules_names)
result = bbot_wrapper.check_scan_output(scan_status, "csv")
ex = ReportExtractor(result, modules_names)
data = ex.extract_by_modules()
t = ex.get_event_types()
data_types = ex.extract_by_event_types("OPEN_TCP_PORT")
