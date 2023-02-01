from reconizer.services.ec2_kali_connect import run_scan_on_remote_kali, sftp_scan_results, clean_scan_results


COMPLETE_FISH_DICT_PATH = "skipfish_dict/complete.wl"
SCAN_DEFAULT_NAME = "scan_results"
secret_name = "prod/ec2_kali/ssh"


def skipfish_entrypoint(domain) -> dict:
    """
    Args:
        domain: must be full like https://your-url.com
    Returns:
        dict: error and scan results
    """
    command = f'skipfish -o {SCAN_DEFAULT_NAME} -S {COMPLETE_FISH_DICT_PATH} -u -k 05:00:00 {domain}'
    run_scan_on_remote_kali(command, secret_name)
    output_scan_filepath = f'{SCAN_DEFAULT_NAME}/index.html'
    result = sftp_scan_results(output_scan_filepath, secret_name)
    clean_scan_results(SCAN_DEFAULT_NAME, secret_name)
    return dict(error=None, response=result)
