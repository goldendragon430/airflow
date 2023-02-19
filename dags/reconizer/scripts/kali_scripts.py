"""
    This file contains all modules that would run on Kali EC2 machine in paris
"""
import json

from reconizer.scripts.kali_helpers import wapiti_extract_vulnerabilites_and_anomalies, \
    wpscan_find_vulnerabilities_from_scan, xsser_xss_xst_by_passer
from reconizer.services.ec2_kali_connect import KaliMachineConn

kali_machine_conn = KaliMachineConn(retries=3, interval=5)


def harvester_entrypoint(domain: str) -> dict:
    filename = "harvester_result"
    command = f'theHarvester -d {domain} -l 250 -f {filename} -b all'
    std_out, std_err = kali_machine_conn.run_command(command)
    result = kali_machine_conn.sftp_scan_results(f'{filename}.json', mode="json")
    return dict(error=std_err, response=result)


def skip_fish_entrypoint(domain) -> dict:
    """
    Args:
        domain: must be full like https://your-url.com
    """
    complete_fish_dict_path = "skipfish_dict/complete.wl"
    scan_name = "skip_fish_results"
    command = f'skipfish -o {scan_name} -S {complete_fish_dict_path} -u -k 05:00:00 {domain}'
    stdout, std_err = kali_machine_conn.run_scan_on_remote_kali(command)
    if not std_err:
        output_scan_filepath = f'{scan_name}/index.html'
        result = kali_machine_conn.sftp_scan_results(output_scan_filepath, mode="html")
        kali_machine_conn.clean_scan_results(scan_name)
        return dict(error=None, response=result)
    else:
        return dict(error=std_err, response=None)


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
        wafs = [item for item in result if item.get("detected", False)]
        kali_machine_conn.clean_file_output(filename)
        return dict(error=None, response=wafs)
    else:
        return dict(error=std_err, response=None)


def ssl_scan_entrypoint(domain: str) -> dict:
    command = f'sslscan --ocsp --connect-timeout=15 --sleep=25 {domain}'
    std_out, std_err = kali_machine_conn.run_command(command)
    if std_err:
        return dict(error=std_err, response=None)
    else:
        return dict(error=None, response=std_out)


def wapiti_entrypoint(domain: str) -> dict:
    filename = "wapiti_report.json"
    full_domain = f'https://{domain}'
    command = f'wapiti -u {full_domain} -m common -f json -o {filename}'
    std_out, std_err = kali_machine_conn.run_command(command)
    if not std_err:
        report = kali_machine_conn.sftp_scan_results(filename, mode="json")
        response = wapiti_extract_vulnerabilites_and_anomalies(report)
        output = dict(error=None, response=response)
    else:
        output = dict(error=std_err, response=None)

    kali_machine_conn.clean_file_output(filename)
    return output


def wpscan_entrypoint(domain: str, api_key: str) -> dict:
    """_summary_
    Args:
        domain: preferable with https -> i.e https://snoopdogg.com/
        api_key (str): wpscan api token
    """
    command = f'wpscan --url {domain} --random-user-agent --format json --api-token {api_key} --detection-mode mixed'
    std_out, std_err = kali_machine_conn.run_command(command)
    if not std_err:
        data = json.loads(std_out)
        vulnerabilities = wpscan_find_vulnerabilities_from_scan(data)
        return dict(error=None, response=vulnerabilities)
    else:
        return dict(error=std_err, response=None)


# bbot is more intensive if you just want to run sublist3r simple and fast use sublist3r_entrypoint_light
def sublist3r_entrypoint_light(domain: str) -> dict:
    command = f'sublist3r -d {domain}'
    std_out, std_err = kali_machine_conn.run_command(command)
    if not std_err:
        return dict(error=None, response=std_out)
    else:
        return dict(error=std_err, response=None)


def xsser_entrypoint(domain: str) -> dict:
    """
    Args:
        domain:  must be full like https://your-site.com
    """
    by_passers = xsser_xss_xst_by_passer()
    errors, outputs = [], []
    for header in by_passers:
        command = f'xsser -u {domain} -p {header}'
        std_out, std_err = kali_machine_conn.run_command(command)
        errors.append(std_err)
        outputs.append(std_out)

    return dict(error=errors, response=outputs)


def nmap_entrypoint(domain: str) -> dict:
    command = f'nmap --max-rtt-timeout 50ms {domain} -Pn'
    vulnerability_check_command = f'nmap -p80 --script http-google-malware {domain}'
    std_out, std_err = kali_machine_conn.run_command(command)
    vulnerability_out, vulnerability_err = kali_machine_conn.run_command(vulnerability_check_command)
    if not std_err and not vulnerability_err:
        response = [std_out, vulnerability_out]
        return dict(error=None, response=response)
    else:
        error = [std_err, vulnerability_err]
        return dict(error=error, response=None)
