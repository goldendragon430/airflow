"""
    This file contains all modules that would collect data directly from api without connecting to new machines
"""
import requests


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
