"""
    All function related to kali tools
    Name convention : (kali-tool-name)_(function-name)
"""
import itertools
from typing import List


def wapiti_extract_vulnerabilites_and_anomalies(content: dict) -> dict:
    """_summary_
    Args:
        data (dict): wapiti report as json

    Returns:
        dict: vulnerabiilites found
    """
    res_vuln = [v for v in content["vulnerabilities"].values() if len(v) > 0]
    vulnerabilites = list(itertools.chain.from_iterable(res_vuln))
    res_anom = [v for v in content["anomalies"].values() if len(v) > 0]
    anomalies = list(itertools.chain.from_iterable(res_anom))
    return dict(vulnerabilites=vulnerabilites, anomalies=anomalies)


def wpscan_find_vulnerabilities_from_scan(data: dict) -> list:
    vulnerabilities = []
    # data = json.loads(output.decode("utf-8"))
    for plugin in data["plugins"].values():
        for vuln in plugin["vulnerabilities"]:
            vulnerabilities.append(vuln)
    for vers_vul in data["version"]["vulnerabilities"]:
        vulnerabilities.append(vers_vul)
    for theme_vuln in data["main_theme"]["vulnerabilities"]:
        vulnerabilities.append(theme_vuln)
    return vulnerabilities


def xsser_xss_xst_by_passer() -> List[str]:
    """
        Work in progess
    Returns:
        all xss headers that can be used to pass wafs
    """
    by_passers = ["WIP"]
    return by_passers
