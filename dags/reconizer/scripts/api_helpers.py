"""
    All function related directly to Api scripts
    Name convention : (API_company)_(function-name)
    Further research:
        1.  https://api.xforce.ibmcloud.com/doc/
        2. XXXXXX- XXXX
"""
import socket

import requests


def xforce_retireve_vulnerability_info(vulnerability_id: str, auth) -> dict:
    """_summary_
    Args:
        vulnerability_id (str): an example CVE-2014-2601
        auth: key and password for xforce
    Returns:
        dict: type descripiton and risk level
    """
    url = f'https://api.xforce.ibmcloud.com/vulnerabilities/search/{vulnerability_id.upper()}'
    try:
        response = requests.get(url, auth=auth, timeout=60).json()
        return dict((k, response[0][k]) for k in ["type", "description", "risk_level"])
    except Exception as err:
        pass
    return {}


def apollo_pagination(domain: str, api_key: str) -> list:
    session = requests.Session()
    url = "https://api.apollo.io/v1/mixed_people/search"
    data = {"q_organization_domains": domain, "api_key": api_key, "page": 1}
    currP, totalP = 1, 2
    while currP <= totalP:
        data["page"] = currP
        page = session.post(url, data=data).json()
        totalP = page["pagination"]["total_pages"]
        currP += 1
        people = []
        for person in page["people"]:
            people.append({k: v for k, v in person.items() if v is not None})
        yield people


def shodan_query_location(shodan_object, domain: str):
    try:
        ip = socket.gethostbyname(domain)
        data = shodan_object.host(ip)
        res = {}
        for column in ["country_name", "city", "latitude", "longitude"]:
            res[column] = data[column]
        return res
    except Exception as err:
        return {}
