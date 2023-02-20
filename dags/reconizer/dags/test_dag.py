# from datetime import datetime
#
# from airflow.decorators import dag
#
# from reconizer.common.raw_data_operator import RawDataOperator
# from reconizer.scripts.bbot_scripts import bbot_cli_entrypoint
#
# """
# Assets: domain/subdomain/url/port/people/emails/ip
# Vulnerabilities: for domain/subdomain/url/ip
# """
#
#
# @dag(dag_id="test_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
# def test_dag(**kwargs):
#     RawDataOperator(task_id="bbot_general", fn=bbot_cli_entrypoint, op_args=[""])
#
#
# Dag = test_dag()
