from datetime import datetime

from airflow.decorators import dag
from airflow.models import Variable

from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.bbot_scripts import shodan_dns_entrypoint


@dag(dag_id="test_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def main_dag(**kwargs):
    RawDataOperator(task_id="ttt", fn=shodan_dns_entrypoint, op_args=["provide domain in your conf",
                                                                      Variable.get("secrets",
                                                                                   deserialize_json=True).get(
                                                                          "shodan_dns")])


Dag = main_dag()
