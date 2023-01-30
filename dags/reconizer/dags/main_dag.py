from airflow.models import Variable
from airflow.decorators import dag, task
from datetime import datetime
from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.apollo import apollo_entrypoint


@dag(dag_id="main_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def main_dag():

    RawDataOperator(task_id="apollo", fn=apollo_entrypoint,
                    op_args=["www.ynet.co.il", Variable.get("secrets", deserialize_json=True).get("apollo")])


Dag = main_dag()
