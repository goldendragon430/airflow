from datetime import datetime

from airflow.decorators import dag
from airflow.models import Variable

from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.bbot_scripts import bbot_events_iteration

"""
Assets: domain/subdomain/url/port/people/emails/ip
Vulnerabilities: for domain/subdomain/url/ip
"""

NUM_OF_MODULES_PER_SCAN = 6
TOTAL_NUM_OF_BBOT_MODULES = 60


@dag(dag_id="test_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def test_dag(**kwargs):
    RawDataOperator(task_id=f'bbot_general', fn=bbot_events_iteration,
                    op_args=["", Variable.get("secrets", deserialize_json=True)])


Dag = test_dag()
