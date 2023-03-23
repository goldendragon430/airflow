import json
from typing import Any, Callable, Collection, Mapping

from airflow.models import Variable
from airflow.models.baseoperator import BaseOperator
from airflow.providers.amazon.aws.hooks.s3 import S3Hook
from airflow.utils.decorators import apply_defaults
import awswrangler as wr
import pandas as pd
import boto3


def raw_data_bucket():
    return Variable.get("raw_data_bucket")


def raw_data_path(run_id, dag_id, task_id):
    return f"{run_id}/{dag_id}/{task_id}"


class RawDataOperator(BaseOperator):

    @apply_defaults
    def __init__(self, *args, fn: Callable,
                 op_args: Collection[Any] | None = None,
                 op_kwargs: Mapping[str, Any] | None = None, **kwargs):
        super().__init__(*args, **kwargs)

        self.callable = fn
        self.op_args = op_args or ()
        self.op_kwargs = op_kwargs or {}

    def execute(self, context):
        bucket = raw_data_bucket()
        data_path = raw_data_path(
            context['dag_run'].run_id, context['dag_run'].dag_id, context['task'].task_id)
        # This line override the first arg and set the domain from configuration
        self.op_args[0] = context["dag_run"].conf["kwargs"]["domain"]
        result = self.execute_callable()
        result_as_string = json.dumps(result)

        s3_hook = S3Hook()
        s3_hook.load_string(bucket_name=bucket,
                            key=data_path, string_data=result_as_string)

        df = pd.DataFrame({"id": [1, 2], "value": ["foo", "boo"]})
        my_session = boto3.Session(region_name="eu-central-1")

        # wr.s3.to_parquet(
        #     df=df,
        #     path=f"s3://r-mor-airflow-raw-data-tomer/{context['dag_run'].run_id}/",
        #     dataset=True,
        #     database="raw_data",
        #     table="my_table",
        #     boto3_session=my_session
        # )

        return result

    def execute_callable(self) -> Any:
        return self.callable(*self.op_args, **self.op_kwargs)
