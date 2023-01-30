import json
import subprocess


def wafw00f_entrypoint(domain: str) -> dict:
    """_summary_
    Args:
        domain (str): url or domain

    Returns:
        dict: error + wafs detected
    """
    filename = f'wafw00f_{domain}.json'
    command = ["wafw00f", domain, "-v", "-a", "-f", "json","-o", filename]
    result = subprocess.run(command, timeout=120, check=True)
    with open(filename, mode="r") as file:
        wafs = json.loads(file.read())
        print(wafs)
    subprocess.run(["rm", filename], timeout=5, check=True)
    return dict(error=result.stderr, response=wafs)
