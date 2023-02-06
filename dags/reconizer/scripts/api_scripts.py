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
