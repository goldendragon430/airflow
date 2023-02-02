import json
import subprocess
import os
from bbot.scanner.scanner import Scanner

SCAN_DEFAULT_NAME = "scan_results"


class BbotWrapper:

    @staticmethod
    def add_api_key(module_name: str, api_key: str) -> list:
        module_api_key_config = f'modules.{module_name}.api_key={api_key}'
        return ["-c", module_api_key_config]

    @staticmethod
    def create_config_from_secrets(secrets: dict):
        bbot_config = {}
        for key, value in secrets.items():
            if "key" in key:
                continue
            bbot_config[key] = dict(api_key=value)

        # because aws secrets can't store nested json properly
        bbot_config["censys"] = dict(api_id= secrets["censys_key"], api_secret=secrets["censys_pass"])

        return dict(modules=bbot_config)

    def __init__(self, domain: str, secrets: dict):
        self.domain = domain
        self.directory = os.getcwd()
        self.config = self.create_config_from_secrets(secrets)

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

    def clean_scan_folder(self) -> None:
        try:
            subprocess.run(["rm", "-r", f'{self.directory}/{SCAN_DEFAULT_NAME}'], timeout=5, check=True)
        except Exception:
            pass

    def activate_scan(self, *args):
        err, events = self.run_scan_cli(args)
        self.clean_scan_folder()
        return err, events

    def run_scan_python(self, module_name: str, api_key: str = None):
        config = dict(output_dir=self.directory)
        if api_key:
            api_conf = {module_name: {"api_key": api_key}}
            config.update(modules=api_conf)
        scan = Scanner(self.domain, modules=[module_name], config=config, output_modules=["json"],
                       name=SCAN_DEFAULT_NAME)
        for event in scan.start():
            print(event)
        return scan.status

    def check_scan_output(self, status) -> tuple:
        if status == "failed":
            return Exception(f'error running scan with status: {status}'), None
        else:
            events = []
            with open(f'{self.directory}/{SCAN_DEFAULT_NAME}/output.json', mode="r") as file:
                for line in file:
                    events.append(json.loads(line))
            self.clean_scan_folder()
            return None, events
