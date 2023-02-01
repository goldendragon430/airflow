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