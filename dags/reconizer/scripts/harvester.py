from dags.services.ec2_kali_connect import run_command_on_remote_kali


def harvester_entrypoint(domain: str) -> dict:
    """_summary_
    Args:
        domain (str): url to scan
    Returns:
        dict: error if any and response from harvester tool
    """
    secret_name= "prod/ec2_kali/ssh"
    command = f'theHarvester -d {domain} -b all'
    std_out, std_err = run_command_on_remote_kali(command, secret_name)
    return dict(error=std_err, response=std_out)
