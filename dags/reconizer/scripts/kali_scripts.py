"""
    This file contains all modules that would run on Kali EC2 machine in paris
"""
import json

from reconizer.services.ec2_kali_connect import KaliMachineConn
from reconizer.scripts.wapiti import extract_vulnerabilites_and_anomalies
from reconizer.scripts.wpscan import find_vulnerabilities_in_wpscan_output

kali_machine_conn = KaliMachineConn(retries=3, interval=5)


def harvester_entrypoint(domain: str) -> dict:
    command = f'theHarvester -d {domain} -l 500 -b google'
    std_out, std_err = kali_machine_conn.run_command(command)
    return dict(error=std_err, response=std_out)


def skip_fish_entrypoint(domain) -> dict:
    """
    Args:
        domain: must be full like https://your-url.com
    """
    complete_fish_dict_path = "skipfish_dict/complete.wl"
    scan_name = "skip_fish_results"
    command = f'skipfish -o {scan_name} -S {complete_fish_dict_path} -u -k 05:00:00 {domain}'
    kali_machine_conn.run_scan_on_remote_kali(command)
    output_scan_filepath = f'{scan_name}/index.html'
    result = kali_machine_conn.sftp_scan_results(output_scan_filepath)
    kali_machine_conn.clean_scan_results(scan_name)
    return dict(error=None, response=result)


def wafw00f_entrypoint(domain: str) -> dict:
    """_summary_
    Args:
        domain (str): url or domain
    """
    filename = "wafw00f_output.json"
    command = f'wafw00f {domain} -v -a -f json -o {filename}'
    std_out, std_err = kali_machine_conn.run_command(command)
    if not std_err:
        result = kali_machine_conn.sftp_scan_results(filename, mode="json")
        kali_machine_conn.clean_file_output(filename)
        return dict(error=None, response=result)
    else:
        return dict(error=std_err, response=None)


def ssl_scan_entrypoint(domain: str) -> dict:
    command = f'sslscan --ocsp --connect-timeout=15 --sleep=75 {domain}'
    std_out, std_err = kali_machine_conn.run_command(command)
    if std_err:
        return dict(error=std_err, response=None)
    else:
        return dict(error=None, response=std_out)


def wapiti_entrypoint(domain: str) -> dict:
    filename = "wapiti_report.json"
    command = f'wapiti -u {domain} -f json -o filename'
    std_out, std_err = kali_machine_conn.run_command(command)
    if not std_err:
        report = kali_machine_conn.sftp_scan_results(filename, mode="json")
        response = extract_vulnerabilites_and_anomalies(report)
        output = dict(error=None, response=response)
    else:
        output = dict(error=std_err, response=None)

    kali_machine_conn.clean_file_output(filename)
    return output


def wpscan_entrypoint(domain: str, api_key: str) -> dict:
    """_summary_
    Args:
        api_key (str): wpscan api token
    """
    command = f'wpscan --url {domain} --random-user-agent --format json --api-token {api_key}' \
              f' --ignore-main-redirect --force detection-mode mixed'
    std_out, std_err = kali_machine_conn.run_command(command)
    if not std_err:
        data = json.loads(std_out)
        vulnerabilities = find_vulnerabilities_in_wpscan_output(data)
        return dict(error=None, response=vulnerabilities)
    else:
        return dict(error=std_err, response=None)


d = wpscan_entrypoint("walla.co.il", "0aKpORSMkvP60g34PWXAWk4Ev7iWma4bLkyDvubu8q8")
print(d.keys())
print(d.values())