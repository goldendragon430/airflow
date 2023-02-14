import json
import os
import subprocess
from typing import Tuple

import pandas as pd
from bbot.scanner.scanner import Scanner

from reconizer.services.user_defined_exceptions import PartiallyDataError


def add_api_key_to_config(config_str: str) -> list:
    return ["-c", config_str]


def run_scan(domain, **kwargs):
    dict_args = dict(config=dict(output_dir=os.getcwd()), name=f'{kwargs["modules"][0]}_scan')
    kwargs.update(dict_args)
    scan = Scanner(domain, **kwargs)
    for event in scan.start():
        print(event)

    if scan.status == "FINISHED":
        result = get_scan_result(**kwargs)
        # clean scan folder
        subprocess.run(["rm", "-r", kwargs["name"]], timeout=5, check=True)
        return result

    raise PartiallyDataError("test")


def get_scan_result(filepath: str, mode: str):
    if mode == "json":
        events = []
        with open(filepath, mode="r") as file:
            for line in file:
                events.append(json.loads(line))
        return events
    elif mode == "csv":
        return pd.read_csv(filepath)


def run_scan_cli(domain: str, bbot_module: str, api_config: str = None) -> Tuple[bool, str]:
    """_summary_
    args:
        domain: domain to scan, preferable full like http://your-site.org
        bbot_module: module to use like sslcert, sublist3r etc'
        api_key: if necessary
    Returns:
        _type_: error if any and json output of scan
    """
    output_format = "json"
    name = f'{bbot_module}_scan'
    command = ["bbot", "-t", domain, "-o", os.getcwd(), "-n", name, "-m", bbot_module, "-y",
               "--ignore-failed-deps", "-om", output_format]
    if api_config:
        command += add_api_key_to_config(api_config)

    try:
        subprocess.check_call(command, timeout=180)
        return True, f'{name}/output.json'
    except Exception as err:
        return False, str(err)


def clean_scan_folder(scan_folder: str) -> None:
    try:
        subprocess.run(["rm", "-r", scan_folder], timeout=5, check=True)
    except subprocess.CalledProcessError as err:
        pass
    except OSError as err:
        pass


def run_bbot_module(domain: str, bbot_module: str, api_config: str = None) -> dict:
    scan_succeeded, output = run_scan_cli(domain=domain, bbot_module=bbot_module, api_config=api_config)
    if scan_succeeded:
        report = get_scan_result(filepath=output, mode="json")
        clean_scan_folder(scan_folder=f'{bbot_module}_scan')
        return dict(error=None, response=report)
    else:
        return dict(error=output, response=None)


def flag_cli_run(domain: str, flag: str) -> Tuple[bool, str]:
    output_format = "json"
    name = f'{flag}_scan'
    command = ["bbot", "-t", domain, "-f", flag, "-o", os.getcwd(), "-n", name, "-y", "--ignore-failed-deps", "-om",
               output_format]
    try:
        subprocess.check_call(command, timeout=180)
        return True, f'{name}/output.json'
    except Exception as err:
        return False, str(err)


def run_bbot_flag(domain: str, flag: str) -> dict:
    scan_succeeded, output = flag_cli_run(domain=domain, flag=flag)
    if scan_succeeded:
        report = get_scan_result(filepath=output, mode="json")
        clean_scan_folder(scan_folder=f'{flag}_scan')
        return dict(error=None, response=report)
    else:
        return dict(error=output, response=None)
