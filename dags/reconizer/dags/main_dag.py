from datetime import datetime

from airflow.decorators import dag
from airflow.models import Variable

from reconizer.common.raw_data_operator import RawDataOperator
from reconizer.scripts.api_scripts import apollo_entrypoint, viewdns_subdomains, \
    xforce_entrypoint
from reconizer.scripts.bbot_scripts import all_modules_bbot_cli_entrypoint, cloud_buckets_entrypoint, \
    emails_entrypoint, \
    subdomains_flag_entrypoint
from reconizer.scripts.kali_scripts import harvester_entrypoint, wafw00f_entrypoint, wapiti_entrypoint


@dag(dag_id="main_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
def main_dag(**kwargs):
    secrets = Variable.get("secrets", deserialize_json=True)

    # emails
    RawDataOperator(task_id="emails_bbot", fn=emails_entrypoint, op_args=["provide domain in your conf"])

    # subdomains
    RawDataOperator(task_id="subdomains_bbot", fn=subdomains_flag_entrypoint, op_args=["provide domain in your conf"])

    RawDataOperator(task_id="subdomains_viewdns", fn=viewdns_subdomains,
                    op_args=["provide domain in conf", secrets.get("view_dns")])

    # cloud buckets
    RawDataOperator(task_id="cloudbuckets_bbot", fn=cloud_buckets_entrypoint, op_args=["provide domain in your conf"])

    # malwares
    RawDataOperator(task_id="malwares_xforce", fn=xforce_entrypoint,
                    op_args=["provide domain in your conf", secrets.get("xforce_key"), secrets.get("xforce_pass")])

    # vulnerabilities
    RawDataOperator(task_id="vulnerabilities_wapiti", fn=wapiti_entrypoint, op_args=["provide domain in your conf"])

    # ips
    RawDataOperator(task_id="ips_harvester", fn=harvester_entrypoint, op_args=["provide domain in your conf"])
    """
        harvester hold different info, for  the ips extract field in the response["ips"]
    """

    RawDataOperator(task_id="all_bbot", fn=all_modules_bbot_cli_entrypoint, op_args=["provide domain in your conf"])
    """
        bbot output is json -> ips list stores in response["ips"]
                               buckets stores in response["buckets"] 
    """

    # people
    RawDataOperator(task_id="people_apollo", fn=apollo_entrypoint,
                    op_args=["provide domain", secrets.get("apollo")])

    # wafs
    RawDataOperator(task_id="wafs_wafw00f", fn=wafw00f_entrypoint, op_args=["provide domain conf"])


Dag = main_dag()
