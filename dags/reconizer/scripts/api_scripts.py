"""
    This file contains all modules that would collect data directly from api without connecting to new machines
"""
import itertools
import json
import socket
from typing import List

import requests
from requests.auth import HTTPBasicAuth

from reconizer.scripts.api_helpers import apollo_pagination
from reconizer.services.paginationHandler import wrapped_get_request, wrapped_post_request


def have_i_been_pawned_entrypoint(domain: str, api_key: str) -> dict:
    result = {}
    base_url = "https://haveibeenpwned.com/api/v3"
    breachs_url = f'{base_url}/breaches'
    params = {"domain": domain}
    headers = {
        'hibp-api-key': api_key,
        'timeout': '10'
    }
    response = requests.get(breachs_url, params=params, headers=headers)
    if response.ok:
        result = dict(error=None, response=response.json())
    else:
        message = f"{breachs_url} returns {response.status_code} please check your params\n"
        result = dict(error=message, response=None)
    return result


def apollo_entrypoint(domain: str, api_key: str) -> dict:
    people = list()
    for persons in apollo_pagination(domain, api_key):
        people.append(persons)

    result = list(itertools.chain.from_iterable(people))
    return dict(error=None, response=result)


def signal_hire_entrypoint(search_items: List[str], api_key: str) -> dict:
    """
    Args:
        search_items: Array of LinkedIn urls, emails or phones -> i.e ["https://www.linkedin.com/in/url1", "test@email.com"]
        api_key: signal hire api auth key
    """
    api_dict = dict(apiKey=api_key)
    search_url = "https://www.signalhire.com/api/v1/candidate/search"
    payload = json.dumps(dict(items=search_items))
    try:
        resp = wrapped_post_request(search_url, api_dict, payload)
        request_id = resp["requestId"]
    except Exception as err:
        return dict(error=err, response=None)
    else:
        search_result_url = f'https://www.signalhire.com/api/v1/candidate/request/{request_id}'
        try:
            resp = wrapped_get_request(search_result_url, api_dict)
            result = dict(filter(lambda item: item[1]["status"] == "success", resp.items()))
            return dict(error=None, response=result)
        except Exception as err:
            return dict(error=err, response=None)


def view_dns_entrypoint(domain: str, api_key: str) -> dict:
    """_summary_
    Args:
        domain (str): url to scan
        api_key (str): view dns api key
    """
    try:
        port_scan_url = f'https://api.viewdns.info/portscan/?host={domain}&apikey={api_key}&output=json'
        reverse_ip_url = f'https://api.viewdns.info/reverseip/?host={domain}&apikey={api_key}&output=json'
        port_scan_response = requests.get(port_scan_url, timeout=30)
        reverse_ip_response = requests.get(reverse_ip_url, timeout=30)
        if port_scan_response.ok and reverse_ip_response.ok:
            port_data = port_scan_response.json()["response"]["port"]
            reverse_data = reverse_ip_response.json()["response"]["domains"]
            ports_open = list(filter(lambda port: port["status"] == "open", port_data))
            ports_closed = list(filter(lambda port: port["status"] != "open", port_data))
            domain_found = [item["name"] for item in reverse_data]
            result = dict(ports_open=ports_open, ports_closed=ports_closed, domains=domain_found)
            return dict(error=None, response=result)
    except requests.RequestException as err:
        return dict(error=err, response={})
    except KeyError as key_error:
        return dict(error=key_error, response=None)
    else:
        # one of the api calls return status code that is not 200x
        err = {"port_status_code": port_scan_response.status_code,
               "reverse_ip_status_code": reverse_ip_response.status_code}
        return dict(error=err, response={})


def xforce_entrypoint(domain: str, api_key: str, api_pass: str) -> dict:
    """_summary_
    Args:
        domain (str): _description_
        api_key (str): XFORCE_KEY
        api_pass (str): XFORCE_PASS

    Returns:
        dict: malwares found and dns info
    """
    auth = HTTPBasicAuth(api_key, api_pass)
    base_api_url = "https://api.xforce.ibmcloud.com"
    malware_url = f'{base_api_url}/url/malware/{domain}'

    try:
        malware_response = requests.get(malware_url, auth=auth, timeout=60).json()
        return dict(error=None, response=malware_response.get("malware", []))
    except Exception as err:
        return dict(error=err, response=None)


def rocket_reach_entrypoint(domain: str, api_key: str) -> dict:
    url = "https://rocketreach.co/api/v2/company/lookup/"
    headers = {"Api-Key": api_key}
    payload = dict(domain=domain)
    response = requests.get(url, headers=headers, params=payload)
    if response.ok:
        return dict(error=None, response=response.json())
    return dict(error=response.text, response=None)


def viewdns_subdomains(domain: str, api_key: str) -> dict:
    ip = socket.gethostbyname(domain)
    domains = []
    reverse_ip_url = f'https://api.viewdns.info/reverseip/?host={ip}&apikey={api_key}&output=json'
    response = requests.get(reverse_ip_url, timeout=30)
    if response.ok:
        data = response.json()["response"]
        domains_count = int(data["domain_count"])
        if domains_count > 0:
            for domain in data["domains"]:
                domains.append(domain["name"])

    return dict(error=None, response=domains)
