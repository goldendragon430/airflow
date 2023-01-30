# DAG exhibiting task flow paradigm in airflow 2.0
# https://airflow.apache.org/docs/apache-airflow/2.0.2/tutorial_taskflow_api.html
# Modified for our use case

import json
import os
from airflow.decorators import dag, task
from airflow.utils.dates import days_ago

from reconizer.common.raw_data_operator import RawDataOperator


# These args will get passed on to each operator
# You can override them on a per-task basis during operator initialization
default_args = {
    'owner': 'airflow',
}

def call_me(data):
    return data

@dag(default_args=default_args, schedule_interval="@daily", start_date=days_ago(2), tags=['example'])
def example_dag_with_raw_data_operator():

    RawDataOperator(task_id="test", callable=call_me, op_args=[
                    '{"1001": 301.27, "1002": 433.21, "1003": 502.22}'])


dag_with_taskflow_api = example_dag_with_raw_data_operator()
