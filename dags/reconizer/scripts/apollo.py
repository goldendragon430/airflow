import requests


def run_apollo(url, data):
    """_summary_
    Args:
        url (_type_): url to scan
        data (_type_): body for post request to apollo api
    Raises:
        ValueError: _description_
        ValueError: _description_
    Returns:
        _type_: responses
    """
    try:
        responses = []
        response = requests.post(url, data=data, timeout=60)
        total_pages = response.json()["pagination"]["total_pages"]
        print(total_pages)
        for page_number in range(1,  total_pages + 1):
            data["page"] = page_number
            try:
                response = requests.post(url, data, timeout=60)
                responses.append(response.json())
            except requests.exceptions.RequestException as err:
                raise Exception(err)
    except requests.exceptions.RequestException as err:
        raise Exception(err)
    else:
        return responses


def apollo_entrypoint(domain: str, api_key: str) -> dict:
    """_summary_
    Args:
        domain (str): url to scan
        api_key (str): apollo api key

    Returns:
        dict: error and findings
    """
    url = "https://api.apollo.io/v1/mixed_people/search"
    data = {"q_organization_domains": domain, "api_key": api_key, "page": 1}
    try:
        responses = run_apollo(url, data)
    except Exception as err:
        return dict(error=err, response={})
    else:
        return dict(error={}, response=responses)