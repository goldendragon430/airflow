from reconizer.services.bbot_handler import BbotWrapper


def sslcert_entrypoint(domain: str) -> dict:
    bb = BbotWrapper(domain=domain)
    bbot_module = "sslcert"
    err, scan_result = bb.activate_scan(bbot_module)
    data = extract_info_from_ssl_scan(scan_result) if not err else scan_result
    return dict(error=err, response=data)


def extract_info_from_ssl_scan(scan_result: list) -> list:
    list_of_keys = ["type", "data", "resolved_hosts", "module"]
    return [dict(map(lambda key: (key, event.get(key, None)), list_of_keys)) for event in scan_result]
