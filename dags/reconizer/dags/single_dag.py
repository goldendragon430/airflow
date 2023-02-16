from datetime import datetime

from airflow.decorators import dag
from airflow.models import Variable

from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.api_scripts import apollo_extract_emails


@dag(dag_id="single_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def main_dag(**kwargs):
    RawDataOperator(task_id="apollo", fn=apollo_extract_emails,
                    op_args=["provide domain", Variable.get("secrets", deserialize_json=True).get("apollo")])


Dag = main_dag()
