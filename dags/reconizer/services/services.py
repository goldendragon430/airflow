from typing import List
import boto3
from botocore.exceptions import ClientError
import json

class AwsHelper:
    def __init__(self, region_name: str, services: List[str], services_with_region: List[str]) -> None:
        self._region_name = region_name
        self._clients = self._set_clients(services, services_with_region)
    
    def _set_clients(self, services: List[str], services_with_region: List[str]) -> dict:
        clients = {}
        for service in services:
            clients[service] = boto3.client(service)
        for service in services_with_region:
            clients[service] = boto3.client(service, region_name=self._region_name)
        
        return clients

    def get_service_client(self, service:str):
        return self._clients.get(service, None)
    
    def retrieve_secret_from_secret_manager(self, secret_name: str, secret_key: str):
        try:
            get_secret_value_response = self._clients["secretsmanager"].get_secret_value(
                SecretId=secret_name
            )
        except ClientError as e:
            # For a list of exceptions thrown, see
            # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
            raise e

        # Decrypts secret using the associated KMS key.
        secret = get_secret_value_response['SecretString']
        return json.loads(secret).get(secret_key)


class TaskValidator:

    @staticmethod
    def _ensure_status_code(response) -> bool:
        return response.status_code >= 200 and response.status_code <= 204

    def __init__(self, s3_client, s3_bucket) -> None:
        self._s3_client = s3_client
        self._s3_bucket = s3_bucket
    
    def _check_response(self, response) -> str:
        return json.dumps(response.json()) if self._ensure_status_code(response) else {"error": response}

    def _write_response_output(self, response, filename: str):
        self._s3_client.put_object(Bucket=self._s3_bucket, Key=filename, Body=self._check_response(response))
    
    def _write_list_output(self, responses: list, filename: str):
        result = ""
        for response in responses:
            result += self._check_response(response)
        self._s3_client.put_object(Bucket=self._s3_bucket, Key=filename, Body=result)
    
    def write_output(self, err, response, filename):
        self._s3_client.put_object(Bucket=self._s3_bucket, Key=filename+"/err.txt", Body=err)
        self._s3_client.put_object(Bucket=self._s3_bucket, Key=filename+"/response", Body=response)


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

