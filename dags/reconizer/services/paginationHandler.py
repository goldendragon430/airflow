import requests
from reconizer.services.user_defined_exceptions import PartiallyDataError


def post_pagination(url: str, data: dict, field_pagination: str):
    responses = []
    try:
        response = requests.post(url, data=data, timeout=60)
        total_pages = response.json()
        for key in field_pagination.split('.'):
            total_pages = total_pages[key]
    except requests.exceptions.RequestException as err:
        raise PartiallyDataError(err)
    except KeyError:
        raise KeyError(f'{field_pagination} not valid , please check response')
    else:
        for page_number in range(2, total_pages + 1):
            data["page"] = page_number
            try:
                response = requests.post(url, data, timeout=60)
                responses.append(response.json())
            except requests.exceptions.RequestException as err:
                raise PartiallyDataError(err)

        return responses
