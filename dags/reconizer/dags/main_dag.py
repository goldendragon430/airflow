import os
from datetime import datetime

from airflow.decorators import dag
from airflow.models import Variable

from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.bbot_scripts import shodan_dns_entrypoint, ssl_cert_entrypoint
from scripts.api_scripts import apollo_entrypoint, have_i_been_pawned_entrypoint, signal_hire_entrypoint, \
    view_dns_entrypoint, xforce_entrypoint
from scripts.kali_scripts import ssl_scan_entrypoint, sublist3r_entrypoint_light, wafw00f_entrypoint, wapiti_entrypoint, \
    wpscan_entrypoint


@dag(dag_id="main_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def main_dag():
    path = os.path.join(os.getcwd(), "bbot_scans")
    if not os.path.exists(path):
        os.mkdir(path)

    # BBot scripts
    RawDataOperator(task_id="shodan_dns", fn=shodan_dns_entrypoint,
                    op_args=["www.ynet.co.il", Variable.get("secrets", deserialize_json=True).get("shodan_dns")])

    RawDataOperator(task_id="sslcert", fn=ssl_cert_entrypoint, op_args=["www.ynet.co.il"])

    # # Api scripts

    RawDataOperator(task_id="haveibeenpawned", fn=have_i_been_pawned_entrypoint,
                    op_args=["www.ynet.co.il", Variable.get("secrets", deserialize_json=True).get("haveibeenpawned")])

    search_items = ["https://www.linkedin.com/in/url1", "test@email.com"]
    RawDataOperator(task_id="signalhire", fn=signal_hire_entrypoint,
                    op_args=[search_items, Variable.get("secrets", deserialize_json=True).get("signal")])

    RawDataOperator(task_id="apollo", fn=apollo_entrypoint,
                    op_args=["www.ynet.co.il", Variable.get("secrets", deserialize_json=True).get("apollo")])

    RawDataOperator(task_id="view_dns", fn=view_dns_entrypoint,
                    op_args=["www.ynet.co.il", Variable.get("secrets", deserialize_json=True).get("view_dns")])

    RawDataOperator(task_id="xforce", fn=xforce_entrypoint,
                    op_args=["www.ynet.co.il", Variable.get("secrets", deserialize_json=True).get("xforce_key"),
                             Variable.get("secrets", deserialize_json=True).get("xforce_pass")])

    # # Kali scripts

    RawDataOperator(task_id="wpscan", fn=wpscan_entrypoint,
                    op_args=["https://snoopdogg.com/", Variable.get("secrets", deserialize_json=True).get("wp_scan")])

    RawDataOperator(task_id="wafw00f", fn=wafw00f_entrypoint, op_args=["www.ynet.co.il"])

    # need to fix dict words for skip fish
    # RawDataOperator(task_id="skipfish", fn=skip_fish_entrypoint, op_args=["https://www.ynet.co.il"])

    RawDataOperator(task_id="sslscan", fn=ssl_scan_entrypoint, op_args=["www.ynet.co.il"])

    RawDataOperator(task_id="wapiti", fn=wapiti_entrypoint, op_args=["www.ynet.co.il"])

    RawDataOperator(task_id="sublist3r", fn=sublist3r_entrypoint_light, op_args=["www.ynet.co.il"])


Dag = main_dag()
