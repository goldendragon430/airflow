"""
    This file contains all modules that would run on Kali EC2 machine in paris
"""
from reconizer.services.ec2_kali_connect import KaliMachineConn


kali_machine_conn = KaliMachineConn(retries=3, interval=5)


def harvester_entrypoint(domain: str) -> dict:
    """_summary_
    Args:
        domain (str): url to scan
    Returns:
        dict: error if any and response from harvester tool
    """
    command = f'theHarvester -d {domain} -l 500 -b google'
    std_out, std_err = kali_machine_conn.run_command(command)
    return dict(error=std_err, response=std_out)


def skip_fish_entrypoint(domain) -> dict:
    """
    Args:
        domain: must be full like https://your-url.com
    Returns:
        dict: error and scan results
    """
    complete_fish_dict_path = "skipfish_dict/complete.wl"
    scan_name = "skip_fish_results"
    command = f'skipfish -o {scan_name} -S {complete_fish_dict_path} -u -k 05:00:00 {domain}'
    kali_machine_conn.run_scan_on_remote_kali(command)
    output_scan_filepath = f'{scan_name}/index.html'
    result = kali_machine_conn.sftp_scan_results(output_scan_filepath)
    kali_machine_conn.clean_scan_results(scan_name)
    return dict(error=None, response=result)
