from datetime import datetime

from airflow.decorators import dag

from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.bbot_scripts import cloud_buckets_entrypoint, \
    emails_entrypoint, \
    subdomains_flag_entrypoint


@dag(dag_id="main_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def main_dag(**kwargs):
    # emails
    RawDataOperator(task_id="emails", fn=emails_entrypoint, op_args=["provide domain in your conf"])

    # subdomains
    RawDataOperator(task_id="subdomains", fn=subdomains_flag_entrypoint, op_args=["provide domain in your conf"])

    # cloud buckets
    RawDataOperator(task_id="cloud_buckets", fn=cloud_buckets_entrypoint, op_args=["provide domain in your conf"])


Dag = main_dag()
