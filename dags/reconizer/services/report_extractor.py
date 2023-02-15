from typing import List

import pandas as pd


# def extract_by_event_types(df, event_type: str, tag: str) -> pd.DataFrame:
#     if event_type in df["Event type"].unique():
#         return df[df["Event type"] == event_type && tag in df[df[""]]]
#     else:
#         print(f" entered invalid event type, please try again")
#         return None


class ReportExtractor:

    def __init__(self, df: pd.DataFrame, modules_names: List[str]):
        self.df = df
        self.modules_names = modules_names

    def extract_by_modules(self) -> dict:
        result = {}
        for name in self.modules_names:
            result[name] = self.df[self.df["Source Module"] == name]
        return result

    def get_event_types(self) -> List[str]:
        return
