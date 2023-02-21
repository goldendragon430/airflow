from datetime import datetime

from airflow.decorators import dag, task
from airflow.models import Variable

from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.bbot_scripts import bbot_events_from_all_modules

"""
Assets: domain/subdomain/url/port/people/emails/ip
Vulnerabilities: for domain/subdomain/url/ip
"""


@dag(dag_id="test_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def test_dag(**kwargs):
    secrets = Variable.get("secrets", deserialize_json=True)

    @task(task_id='report')
    def process_events(**kwargs) -> str:
        print(kwargs)
        domain = kwargs["conf"]["domain"]
        print(domain)
        return bbot_events_from_all_modules(domain, secrets)

    status = process_events()
    if status == "FINISHED":
        RawDataOperator(task_id="bbot_general", fn=process_events, op_args=[""])


Dag = test_dag()
