"""
    This file contains all modules that would collect data directly from api without connecting to new machines
"""
import json
from typing import List

import requests

from reconizer.services.paginationHandler import post_pagination, wrapped_post_request, wrapped_get_request
from reconizer.services.user_defined_exceptions import PartiallyDataError


def have_i_been_pawned_entrypoint(domain: str, api_key: str) -> dict:
    base_url = "https://haveibeenpwned.com/api/v3"
    breach_url = f'{base_url}/breaches'
    params = {"domain": domain}
    headers = {
        'hibp-api-key': api_key,
        'timeout': '2.5'
    }
    response = requests.get(breach_url, params=params, headers=headers)
    return response.json() if response.ok else {}


def apollo_entrypoint(domain: str, api_key: str) -> dict:
    url = "https://api.apollo.io/v1/mixed_people/search"
    data = {"q_organization_domains": domain, "api_key": api_key, "page": 1}
    field_pagination = "pagination.total_pages"
    try:
        responses = post_pagination(url=url, data=data, field_pagination=field_pagination)
    except PartiallyDataError as err:
        return dict(error=err, response=None)
    except KeyError as key_error:
        return dict(error=key_error, response=None)
    else:
        return dict(error=None, response=responses)


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
