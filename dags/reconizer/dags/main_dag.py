from airflow.models import Variable
from airflow.decorators import dag, task
from datetime import datetime
from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.apollo import apollo_entrypoint
from reconizer.scripts.bbot_scripts import shodan_dns_entrypoint
from reconizer.scripts.sslcert import sslcert_entrypoint


@dag(dag_id="main_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def main_dag():

    RawDataOperator(task_id="apollo", fn=apollo_entrypoint,
                    op_args=["www.ynet.co.il", Variable.get("secrets", deserialize_json=True).get("apollo")])

    RawDataOperator(task_id="shodan_dns", fn=shodan_dns_entrypoint,
                    op_args=["www.ynet.co.il", Variable.get("secrets", deserialize_json=True).get("shodan_dns")])

    RawDataOperator(task_id="sslcert", fn=sslcert_entrypoint, op_args=["www.ynet.co.il"])


Dag = main_dag()
