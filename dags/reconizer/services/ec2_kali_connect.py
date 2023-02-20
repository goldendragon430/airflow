import io
import json
import time
from typing import Tuple

import boto3
import paramiko
from bs4 import BeautifulSoup

from reconizer.services.services import get_secret


class KaliMachineConn:

    @staticmethod
    def setup_before_connection():
        # get your instance ID from AWS dashboard
        instance_id = "i-07268b1956ad00330"
        region = "eu-west-3"

        # get instance
        ec2 = boto3.resource('ec2', region_name=region)
        instance = ec2.Instance(id=instance_id)
        instance.wait_until_running()
        current_instance = list(ec2.instances.filter(InstanceIds=[instance_id]))
        ip_address = current_instance[0].public_ip_address
        return ip_address

    @staticmethod
    def read_html_file_in_session(ftp_client, filepath: str):
        with ftp_client.open(filepath, "r") as html_file:
            index = html_file.read()
            return BeautifulSoup(index, 'lxml')

    @staticmethod
    def read_json_file_in_session(ftp_client, filepath: str) -> dict:
        with ftp_client.open(filepath, mode="r") as file:
            return json.loads(file.read())

    def __init__(self, retries: int, interval: int):
        self.pem_key = get_secret("prod/ec2_kali/ssh")
        self.retries = retries
        self.wait_interval = interval
        self.username = "root"

    def ssh_connect_with_retry(self, ssh, ip_address, pem_key, retries):
        if retries > self.retries:
            return False
        privkey = paramiko.RSAKey.from_private_key(io.StringIO(pem_key))
        try:
            retries += 1
            print('SSH into the instance: {}'.format(ip_address))
            ssh.connect(hostname=ip_address,
                        username=self.username, pkey=privkey)
            return True
        except Exception as e:
            print(e)
            time.sleep(self.wait_interval)
            print('Retrying SSH connection to {}'.format(ip_address))
            self.ssh_connect_with_retry(ssh, ip_address, pem_key, retries)

    def run_command(self, command: str) -> Tuple[str, str]:
        ip_address = self.setup_before_connection()

        # connect and run command
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_connect_with_retry(ssh, ip_address, self.pem_key, 0)
            stdin, stdout, stderr = ssh.exec_command(command)
            return stdout.read().decode("utf-8"), stderr.read().decode("utf-8")

    def run_scan_on_remote_kali(self, scan_command: str) -> tuple:
        ip_address = self.setup_before_connection()

        # connect and run command
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_connect_with_retry(ssh, ip_address, self.pem_key, 0)
            stdin, stdout, stderr = ssh.exec_command(scan_command)
            stdout.channel.set_combine_stderr(True)
            output = stdout.readlines()
            return output, stderr

    def sftp_scan_results(self, filepath: str, mode="json"):
        ip_address = self.setup_before_connection()

        # connect and run command
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_connect_with_retry(ssh, ip_address, self.pem_key, 0)
            ftp_client = ssh.open_sftp()
            if mode == "html":
                result = self.read_html_file_in_session(ftp_client, filepath)
            else:
                result = self.read_json_file_in_session(ftp_client, filepath)

            ftp_client.close()
            return result

    def clean_scan_results(self, folder):
        command = f'rm -r {folder}'
        ip_address = self.setup_before_connection()

        # connect and run command
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_connect_with_retry(ssh, ip_address, self.pem_key, 0)
            ssh.exec_command(command)

    def clean_file_output(self, filename: str) -> None:
        command = f'rm {filename}'
        ip_address = self.setup_before_connection()

        # connect and run command
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_connect_with_retry(ssh, ip_address, self.pem_key, 0)
            ssh.exec_command(command)
