import requests


def view_dns_entrypoint(domain: str, api_key: str) -> dict:
    """_summary_
    Args:
        domain (str): url to scan
        api_key (str): view dns api key

    Returns:
        dict: error if any and response
    """
    scans = ["reverseip", "portscan"]
    results = {}
    try:
        for scan in scans:
            url = f'https://api.viewdns.info/{scan}/?host={domain}&apikey={api_key}&output=json'
            response = requests.get(url, timeout=60)
            results[scan] = response.json()
    except requests.RequestException as err:
        return dict(error=err, response={})
    else:
        ports_open = filter(
            lambda port: port["status"] == "open", results["portscan"]["response"]["port"])
        ports_closed = filter(
            lambda port: not port["status"] == "open", results["portscan"]["response"]["port"])
        domain_found = [item["name"]
                        for item in results["reverseip"]["response"]["domains"]]
        output = dict(ports_open=list(ports_open), ports_closed=list(
            ports_closed), domains=domain_found)
        return dict(error=None, response=output)
