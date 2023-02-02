from typing import List
import pandas as pd


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
        return self.df["Event type"].unique()

    def extract_by_event_types(self, event_type: str) -> pd.DataFrame:
        if event_type not in self.get_event_types():
            print(f" entered invalid event type, please try again")
            return None
        else:
            return self.df[self.df["Event type"] == event_type]
