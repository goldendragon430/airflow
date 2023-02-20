from datetime import datetime

from airflow.decorators import dag
from airflow.models import Variable

from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.api_scripts import apollo_entrypoint, viewdns_subdomains, \
    xforce_entrypoint
from reconizer.scripts.bbot_scripts import bbot_cli_entrypoint, subdomains_flag_entrypoint
from reconizer.scripts.kali_scripts import harvester_entrypoint, wafw00f_entrypoint, wapiti_entrypoint


@dag(dag_id="main_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def main_dag(**kwargs):
    secrets = Variable.get("secrets", deserialize_json=True)

    # general bbot output is json -> ips, buckets, emails and events
    RawDataOperator(task_id="general_bbot", fn=bbot_cli_entrypoint, op_args=[""])

    # subdomains
    RawDataOperator(task_id="subdomains_bbot", fn=subdomains_flag_entrypoint, op_args=[""])

    RawDataOperator(task_id="subdomains_viewdns", fn=viewdns_subdomains, op_args=["", secrets.get("view_dns")])

    # malwares
    RawDataOperator(task_id="malwares_xforce", fn=xforce_entrypoint,
                    op_args=["", secrets.get("xforce_key"), secrets.get("xforce_pass")])

    # vulnerabilities
    RawDataOperator(task_id="vulnerabilities_wapiti", fn=wapiti_entrypoint, op_args=[""])

    # harvester hold different info, for  the ips extract field in the response["ips"]
    RawDataOperator(task_id="ips_harvester", fn=harvester_entrypoint, op_args=[""])

    # people
    RawDataOperator(task_id="people_apollo", fn=apollo_entrypoint,
                    op_args=["", secrets.get("apollo")])

    # wafs
    RawDataOperator(task_id="wafs_wafw00f", fn=wafw00f_entrypoint, op_args=[""])


Dag = main_dag()
