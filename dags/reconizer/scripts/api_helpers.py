"""
    All function related directly to Api scripts
    Name convention : (API_company)_(function-name)
    Further research:
        1.  https://api.xforce.ibmcloud.com/doc/
        2. XXXXXX- XXXX
"""

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
