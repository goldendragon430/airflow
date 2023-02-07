import json
import os
import subprocess
import pandas as pd
from bbot.scanner.scanner import Scanner
from reconizer.services.user_defined_exceptions import PartiallyDataError


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


def get_scan_result(**kwargs):
    mode = kwargs["output_modules"][0]
    filepath = f'{kwargs["name"]}/output.{mode}'
    if mode == "json":
        events = []
        with open(filepath, mode="r") as file:
            for line in file:
                events.append(json.loads(line))
        return events
    elif mode == "csv":
        return pd.read_csv(filepath)
