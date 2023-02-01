from typing import Tuple
import boto3
import paramiko
from time import time
from botocore.exceptions import ClientError
import io
from bs4 import BeautifulSoup


def get_secret(secret_name: str):
    region_name = "eu-central-1"
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e
    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response['SecretString']
    return secret


def ssh_connect_with_retry(ssh, ip_address, pem_key, retries):
    if retries > 3:
        return False
    privkey = paramiko.RSAKey.from_private_key(io.StringIO(pem_key))
    interval = 5
    try:
        retries += 1
        print('SSH into the instance: {}'.format(ip_address))
        ssh.connect(hostname=ip_address,
                    username='kali', pkey=privkey)
        return True
    except Exception as e:
        print(e)
        time.sleep(interval)
        print('Retrying SSH connection to {}'.format(ip_address))
        ssh_connect_with_retry(ssh, ip_address, pem_key, retries)


def setup_before_connection(secret_name: str):
    # retrieve pem file from secrets manager
    pem_key = get_secret(secret_name)

    # get your instance ID from AWS dashboard
    instance_id = "i-07268b1956ad00330"
    region = "eu-west-3"

    # get instance
    ec2 = boto3.resource('ec2', region_name=region)
    instance = ec2.Instance(id=instance_id)
    instance.wait_until_running()
    current_instance = list(ec2.instances.filter(InstanceIds=[instance_id]))
    ip_address = current_instance[0].public_ip_address
    return ip_address, pem_key


def run_command_on_remote_kali(command: str, secret_name: str) -> Tuple[str, str]:
    ip_address, pem_key = setup_before_connection(secret_name)

    # connect and run command
    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_connect_with_retry(ssh, ip_address, pem_key, 0)
        stdin, stdout, stderr = ssh.exec_command(command)
        return stdout.read().decode("utf-8"), stderr.read().decode("utf-8")


def run_scan_on_remote_kali(scan_command: str, secret_name: str) -> None:
    ip_address, pem_key = setup_before_connection(secret_name)

    # connect and run command
    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_connect_with_retry(ssh, ip_address, pem_key, 0)
        ssh.exec_command(scan_command)


def read_html_file_in_session(filename: str):
    with open(filename, "r") as html_file:
        index = html_file.read()
        return BeautifulSoup(index, 'lxml')


def sftp_scan_results(filepath, secret_name):
    ip_address, pem_key = setup_before_connection(secret_name)

    # connect and run command
    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_connect_with_retry(ssh, ip_address, pem_key, 0)
        ftp_client = ssh.open_sftp()
        with ftp_client.open(filepath, "r") as html_file:
            index = html_file.read()
            result = BeautifulSoup(index, 'lxml')
        ftp_client.close()
        return result


def clean_scan_results(folder, secret_name):
    command = f'rm -r {folder}'
    ip_address, pem_key = setup_before_connection(secret_name)

    # connect and run command
    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_connect_with_retry(ssh, ip_address, pem_key, 0)
        ssh.exec_command(command)
