from datetime import datetime

from airflow.decorators import dag

from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.bbot_helper import subdomains_entrypoint_internal


@dag(dag_id="test_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def main_dag(**kwargs):
    RawDataOperator(task_id="ttt", fn=subdomains_entrypoint_internal, op_args=["www.ynet.co.il"])


Dag = main_dag()
