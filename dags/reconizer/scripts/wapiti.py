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
