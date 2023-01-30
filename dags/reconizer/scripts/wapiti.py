import json
import subprocess


def extract_vulnerabilites_and_anomalies(data: dict) -> dict:
    """_summary_
    Args:
        data (dict): wapiti report as json

    Returns:
        dict: vulnerabiilites found
    """
    vulnerabilites = dict((k, v) for k,v in data["vulnerabilities"].items() if len(v) > 0)
    anomalies = dict((k, v) for k,v in data["anomalies"].items() if len(v) > 0)
    return dict(vulnerabilites=vulnerabilites, anomalies=anomalies)


def wapiti_entrypoint(domain: str) -> dict:
    """_summary_
    Args:
        domain (str): url to scan
    Returns:
        dict: error if any and wapiti scanner results
    """
    filename = "wapiti_report.json"
    command = ["wapiti", "-u", domain, "-f", "json", "-o", filename]
    result = subprocess.run(command, timeout=120, check=True)
    with open(filename, mode="r", encoding="utf-8") as file:
        report = json.loads(file.read())
        response = extract_vulnerabilites_and_anomalies(report)
    subprocess.run(["rm", filename], timeout=5, check=True)
    return dict(error=result.stderr, response=response)
