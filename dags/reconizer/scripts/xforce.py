import requests
from requests.auth import HTTPBasicAuth

API_URL = 'https://api.xforce.ibmcloud.com'


def search_malwares_for_domain(domain: str, auth) -> dict:
    """_summary_
    Args:
        domain (str): url of domain

    Returns:
        dict[str: int, str: List[dict]]: number of malwares found, list of their descriptions
    """
    url = f'{API_URL}/url/malware/{domain}'
    response = call_xforce_api(url, auth)
    if response:
        return dict((k, response[k]) for k in ["count", "malware"])
    return {}


def retireve_vulnerability_info(vulnerability_id: str, auth) -> dict:
    """_summary_
    Args:
        vulnerability_id (str): an example CVE-2014-2601
    Returns:
        dict: type descripiton and risk level
    """
    url = f'{API_URL}/vulnerabilities/search/{vulnerability_id.upper()}'
    response = call_xforce_api(url, auth)
    if response:
        return dict((k, response[0][k]) for k in ["type", "description", "risk_level"])
    return {}


def retrieve_dns_info(domain: str, auth) -> dict:
    """
    Args:
        domain (str): _description_
    Returns:
        dict: dns information
    """
    url = f'{API_URL}/resolve/{domain}'
    return call_xforce_api(url, auth)


def call_xforce_api(url: str, auth) -> dict:
    """
    Args:
        url (str): api endpoint
        for further help you can check the docs at: https://api.xforce.ibmcloud.com/doc/
    Returns:
        dict: response from x force api
    """
    try:
        response = requests.get(url, auth=auth, timeout=60)
        return response.json()
    except Exception:
        pass


def xforce_entrypoint(domain: str, api_key: str, api_pass:str) -> dict:
    """_summary_
    Args:
        domain (str): _description_
        api_key (str): XFORCE_KEY
        api_pass (str): XFORCE_PASS

    Returns:
        dict: malwares found and dns info
    """
    auth = HTTPBasicAuth(api_key, api_pass)
    malware_info = search_malwares_for_domain(domain, auth)
    dns_info = retrieve_dns_info(domain, auth)
    return dict(malwares=malware_info, dns=dns_info)
