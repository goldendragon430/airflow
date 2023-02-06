from airflow.models import Variable
from airflow.decorators import dag, task
from datetime import datetime
from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.bbot_scripts import shodan_dns_entrypoint, ssl_cert_entrypoint
from reconizer.scripts.api_scripts import have_i_been_pawned_entrypoint, apollo_entrypoint, signal_hire_entrypoint, \
    view_dns_entrypoint
from reconizer.scripts.kali_scripts import wafw00f_entrypoint, skip_fish_entrypoint, ssl_scan_entrypoint, \
    wapiti_entrypoint


@dag(dag_id="main_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def main_dag():

    # bbot scripts
    RawDataOperator(task_id="shodan_dns", fn=shodan_dns_entrypoint,
                    op_args=["www.ynet.co.il", Variable.get("secrets", deserialize_json=True).get("shodan_dns")])

    RawDataOperator(task_id="sslcert", fn=ssl_cert_entrypoint, op_args=["www.ynet.co.il"])

    # Api scripts

    RawDataOperator(task_id="haveibeenpawned", fn=have_i_been_pawned_entrypoint,
                    op_args=["www.ynet.co.il", Variable.get("secrets", deserialize_json=True).get("haveibeenpawned")])

    RawDataOperator(task_id="signalhire", fn=signal_hire_entrypoint,
                    op_args=["www.ynet.co.il", Variable.get("secrets", deserialize_json=True).get("signal")])

    RawDataOperator(task_id="apollo", fn=apollo_entrypoint,
                    op_args=["www.ynet.co.il", Variable.get("secrets", deserialize_json=True).get("apollo")])

    RawDataOperator(task_id="view_dns", fn=view_dns_entrypoint,
                    op_args=["www.ynet.co.il", Variable.get("secrets", deserialize_json=True).get("view_dns")])

    # Kali scripts

    RawDataOperator(task_id="wafw00f", fn=wafw00f_entrypoint, op_args=["www.ynet.co.il"])

    RawDataOperator(task_id="skipfish", fn=skip_fish_entrypoint, op_args=["www.ynet.co.il"])

    RawDataOperator(task_id="sslscan", fn=ssl_scan_entrypoint, op_args=["www.ynet.co.il"])

    RawDataOperator(task_id="wapiti", fn=wapiti_entrypoint, op_args=["www.ynet.co.il"])


Dag = main_dag()
