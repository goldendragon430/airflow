import json
import subprocess
import os


SCAN_DEFAULT_NAME= "scan_results"


class BbotWrapper:
    def __init__(self, domain: str):
        self.domain = domain
        self.directory = os.getcwd()

    def run_scan_cli(self, *args) -> tuple:
        """_summary_
        args:
            bbot_module: module to use like sslcert, sublist3r etc'
            api_key: if necessary
        Returns:
            _type_: error if any and json output of scan
        """
        bbot_module = args[0][0]
        output_format = "json"
        command = ["bbot", "-t", self.domain, "-o", self.directory, "-n", SCAN_DEFAULT_NAME, "-m", bbot_module, "-y",
                       "--ignore-failed-deps", "-om", output_format]
        if len(args) > 1:
            command += self.add_api_key(bbot_module, args[0][1])
        result = subprocess.run(command, timeout=60)
        events = []
        if not result.stderr:
            with open(f'{self.directory}/{SCAN_DEFAULT_NAME}/output.json', mode="r") as file:
                for line in file:
                    events.append(json.loads(line))
            return None, events
        else:
            return result.stderr, None

    def add_api_key(self, module_name: str, api_key: str) -> list:
        module_api_key_config = f'modules.{module_name}.api_key={api_key}'
        return ["-c", module_api_key_config]

    def clean_scan_folder(self) -> None:
        try:
            subprocess.run(["rm", "-r", f'{self.directory}/{SCAN_DEFAULT_NAME}'], timeout=5, check=True)
        except Exception:
            pass

    def activate_scan(self, *args):
        err, events = self.run_scan_cli(args)
        self.clean_scan_folder()
        return err, events
