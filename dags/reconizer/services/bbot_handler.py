import json
import subprocess
import os
import pandas as pd
from bbot.scanner.scanner import Scanner

SCAN_DEFAULT_NAME = "scan_results"


class BbotWrapper:

    @staticmethod
    def parse_json_output(filepath: str) -> dict:
        events = []
        with open(filepath, mode="r") as file:
            for line in file:
                events.append(json.loads(line))
        return events

    @staticmethod
    def add_api_key(module_name: str, api_key: str) -> list:
        module_api_key_config = f'modules.{module_name}.api_key={api_key}'
        return ["-c", module_api_key_config]

    def create_config_from_secrets(self, secrets: dict):
        bbot_config = {}
        for key, value in secrets.items():
            if "key" in key or "pass" in key:
                continue
            bbot_config[key] = dict(api_key=value)

        # because aws secrets can't store nested json properly
        bbot_config["censys"] = dict(api_id=secrets["censys_key"], api_secret=secrets["censys_pass"])
        return dict(modules=bbot_config, output_dir=self.directory)

    def __init__(self, domain: str, secrets: dict):
        self.domain = domain
        self.directory = os.getcwd()
        self.config = self.create_config_from_secrets(secrets)
        self.scan_default_name = "scan_results"

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
        except subprocess.CalledProcessError as err:
            pass
        except OSError as err:
            pass

    def activate_scan(self, *args):
        err, events = self.run_scan_cli(args)
        self.clean_scan_folder()
        return err, events

    def run_scan_python(self, modules_names: list):
        scan = Scanner(self.domain, modules=modules_names, config=self.config, output_modules=["csv"],
                       name=self.scan_default_name, force_start=True)
        for event in scan.start():
            print(event)
        return scan.status

    def check_scan_output(self, status, output_modules: str):
        if status == "failed":
            return Exception(f'error running scan with status: {status}'), None
        else:
            output_file = f'{self.directory}/{SCAN_DEFAULT_NAME}/output.{output_modules}'
            if output_modules == "json":
                result = pd.read_json(output_file)
            elif output_modules == "csv":
                result = pd.read_csv(output_file)
            else:
                result = None

        self.clean_scan_folder()
        return result


"""
secrets = get_secret("airflow/variables/secrets")
bbot_wrapper = BbotWrapper("www.toysrus.com", json.loads(secrets))
modules_names = ["httpx", "shodan_dns", "sslcert", "crt", "azure_tenant", "censys", "dnscommonsrv",
                 "bucket_digitalocean", "bypass403"]
scan_status = bbot_wrapper.run_scan_python(modules_names)
result = bbot_wrapper.check_scan_output(scan_status, "csv")
ex = ReportExtractor(result, modules_names)
data = ex.extract_by_modules()
t = ex.get_event_types()
data_types = ex.extract_by_event_types("OPEN_TCP_PORT")

"""