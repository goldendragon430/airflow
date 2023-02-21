# from datetime import datetime
#
# from airflow.decorators import dag
# from airflow.models import Variable
#
# from reconizer.common.raw_data_operator import RawDataOperator
# from reconizer.scripts.bbot_scripts import bbot_events_from_all_modules
#
# """
# Assets: domain/subdomain/url/port/people/emails/ip
# Vulnerabilities: for domain/subdomain/url/ip
# """
#
# NUM_OF_MODULES_PER_SCAN = 6
#
#
# @dag(dag_id="test_dag", schedule_interval=None, start_date=datetime(2023, 1, 12))
# def test_dag(**kwargs):
#     for i in range(0, 60, NUM_OF_MODULES_PER_SCAN):
#         RawDataOperator(task_id=f'bbot_general_{i}', fn=bbot_events_from_all_modules,
#                         op_args=["", Variable.get("secrets", deserialize_json=True), i, i + NUM_OF_MODULES_PER_SCAN])
#
#
# Dag = test_dag()
