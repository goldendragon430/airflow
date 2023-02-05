"""
    This file contains all modules that would collect data directly from api without connecting to new machines
"""
import requests
from reconizer.services.user_defined_exceptions import PartiallyDataError
from reconizer.services.paginationHandler import post_pagination


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
        return dict(error=err, response={})
    except KeyError as key_error:
        return dict(error=key_error, response={})
    else:
        return dict(error={}, response=responses)
