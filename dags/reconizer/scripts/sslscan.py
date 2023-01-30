from services.ec2_kali_connect import run_command_on_remote_kali


def scan_ssl_certifiactes(domain: str) -> dict:
    secret_name= "prod/ec2_kali/ssh"
    command = f'sslscan --ocsp --connect-timeout=15 --sleep=75 {domain}'
    std_out, std_err = run_command_on_remote_kali(command, secret_name)
    return dict(error=std_err, response=std_out)
