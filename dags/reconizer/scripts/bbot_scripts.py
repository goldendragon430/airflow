from reconizer.services.bbot_handler import BbotWrapper


def general_bbot_entrypoint(domain:str, module_name:str, api_key:str) -> tuple[list, list]:
    bbot_wrapper = BbotWrapper(domain)
    scan_status = bbot_wrapper.run_scan_python(module_name, api_key)
    scan_errors, scan_results = bbot_wrapper.check_scan_output(scan_status)
    return scan_errors, scan_results


def shodan_dns_entrypoint(domain:str, api_key: str) -> tuple[list, list]:
    return general_bbot_entrypoint(domain, "shodan_dns", api_key)
