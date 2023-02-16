from datetime import datetime

from airflow.decorators import dag
from airflow.models import Variable

from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.api_scripts import viewdns_subdomains


@dag(dag_id="single_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def main_dag(**kwargs):
    RawDataOperator(task_id="viewdns_subdomains", fn=viewdns_subdomains, op_args=["provide domain in your conf",
                                                                                  Variable.get("secrets",
                                                                                               deserialize_json=True).get(
                                                                                      "view_dns")])


Dag = main_dag()
