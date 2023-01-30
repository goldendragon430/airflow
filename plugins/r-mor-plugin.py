from airflow.plugins_manager import AirflowPlugin
import os

os.environ["AIRFLOW_VAR_RAW_DATA_BUCKET"] = os.environ["AIRFLOW__RMOR__RAW_DATA_BUCKET"]


class RmorPlugin(AirflowPlugin):

    name = 'rmor_airflow_plugin'
