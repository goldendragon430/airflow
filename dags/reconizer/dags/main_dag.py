from datetime import datetime

from airflow.decorators import dag
from airflow.models import Variable

from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.api_scripts import apollo_entrypoint, viewdns_subdomains, \
    xforce_entrypoint
from reconizer.scripts.bbot_scripts import bbot_events_iteration, bbot_raw_data_task
from reconizer.scripts.kali_scripts import wafw00f_entrypoint, wapiti_entrypoint


@dag(dag_id="main_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def main_dag(**kwargs):
    # this will run all bbot modules and group by their events and write to s3
    RawDataOperator(task_id=f'bbot_filtered_data', fn=bbot_events_iteration,
                    op_args=["", Variable.get("secrets", deserialize_json=True)])

    # raw data output
    RawDataOperator(task_id=f'bbot_raw_data', fn=bbot_raw_data_task,
                    op_args=["", Variable.get("secrets", deserialize_json=True)])

    # subdomains
    RawDataOperator(task_id="subdomains_viewdns", fn=viewdns_subdomains,
                    op_args=["", Variable.get("secrets", deserialize_json=True).get("view_dns")])

    # malwares
    RawDataOperator(task_id="malwares_xforce", fn=xforce_entrypoint,
                    op_args=["", Variable.get("secrets", deserialize_json=True).get("xforce_key"),
                             Variable.get("secrets", deserialize_json=True).get("xforce_pass")])

    # vulnerabilities
    RawDataOperator(task_id="vulnerabilities_wapiti", fn=wapiti_entrypoint, op_args=[""])

    # harvester hold different info, for  the ips extract field in the response["ips"]
    # RawDataOperator(task_id="ips_harvester", fn=harvester_entrypoint, op_args=[""])

    # people
    RawDataOperator(task_id="people_apollo", fn=apollo_entrypoint,
                    op_args=["", Variable.get("secrets", deserialize_json=True).get("apollo")])

    # wafs
    RawDataOperator(task_id="wafs_wafw00f", fn=wafw00f_entrypoint, op_args=[""])


Dag = main_dag()
