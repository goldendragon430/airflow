import json
from typing import Tuple
import requests

class PaginationHandler:

    @staticmethod
    def _find_total_pages(response, field_pagination: str) -> int:
        total_pages = response.json()
        for key in field_pagination.split('.'):
            total_pages = total_pages[key]
        return total_pages

    def __init__(self):
        pass
    
    def handle_post(self, url, data, field_pagination) -> Tuple[str, str]:
        responses = ""
        errors = []

        total_pages = self._find_total_pages(requests.post(url, data=data), field_pagination)
        for page_number in range(1,  total_pages + 1):
            data["page"] = page_number
            try:
                response = requests.post(url, data)
                responses += json.dumps(response.json())
            except Exception as err:
                errors.append(str(err))

        
        return " ".join(errors), responses
    
    def handle_get(self, url, field_pagination):
        total_pages = self._find_total_pages(requests.get(url), field_pagination)
