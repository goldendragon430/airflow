import subprocess
import json


def find_vulnerabilities_in_wpscan_output(data: dict) -> list:
    """_summary_
    Args:
        output (str): output from wpscan in json format
    Returns:
        list: list of vulnerabilities each item is a dict
    """
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


def wpscan_entrypoint(domain: str, api_key: str) -> dict:
    """_summary_
    Args:
        domain (str): url to scan
        api_key (str): wpscan api token
    Returns:
        dict: vulnerabilities and info found from wpscan report
    """
    command = ["wpscan", "--url", domain, "--random-user-agent", "--format", "json",
               "--api-token", api_key, "--ignore-main-redirect", "--force",
               "detection-mode", "mixed"]
    result = subprocess.run(command, capture_output=True, timeout=120)
    data = json.loads(result.stdout.decode("utf-8"))
    vulnerabilities = find_vulnerabilities_in_wpscan_output(data)
    return dict(error=result.stderr, response=vulnerabilities)
