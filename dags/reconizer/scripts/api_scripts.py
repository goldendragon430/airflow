"""
    This file contains all modules that would collect data directly from api without connecting to new machines
"""
import requests

url = "https://haveibeenpwned.com/api/v3/breachedaccount/adobe"
hibp_api_key = "you api goes here"
payload = {}
headers = {
  'hibp-api-key': hibp_api_key,
  'timeout': '2.5'
}

response = requests.request("GET", url, headers=headers, data=payload)
data = response.json()
for k, v in data.items():
  print(k)
  print(v)
