import base64
import socket

import requests


class IBMXForce:

    @staticmethod
    def convert_to_base64(api_key, api_password):
        string_format = f'{api_key}:{api_password}'.encode()
        base64_format = f'Basic {base64.b64encode(string_format).decode()}'
        return base64_format

    def __init__(self, api_key, api_password):
        self._headers = {'Authorization': self.convert_to_base64(api_key=api_key, api_password=api_password)}

        # API RELATED TO IP ADDRESS
        self._ip_category_api = "https://api.xforce.ibmcloud.com/ipr"
        self._ip_report_api = "https://api.xforce.ibmcloud.com/ipr/{ip}"
        self._ip_reputation_api = "https://api.xforce.ibmcloud.com/ipr/history/{ip}"
        self._ip_malware_api = "https://api.xforce.ibmcloud.com/ipr/malware/{ip}"

        # API RELATED TO URL AND DOMAIN
        self._url_category_api = "https://api.xforce.ibmcloud.com/url"
        self._url_report_api = "https://api.xforce.ibmcloud.com/url/{url}"
        self._url_history_api = "https://api.xforce.ibmcloud.com/url/history/{url}"
        self._url_malware_api = "https://api.xforce.ibmcloud.com/url/malware/{url}"

        # API RELATE TO FILE HASH
        self._file_hash_malware_api = "https://api.xforce.ibmcloud.com/malware/{filehash}"
        self._malware_family_api = "https://api.xforce.ibmcloud.com/malware/family/{family_name}"

        # API REALTED TO WHOIS
        self._whois_api = "https://api.xforce.ibmcloud.com/whois/{host}"

    #   PROVIDE IP ADDRESS TO GET INFORMATION RELATED TO RESPSECTIVE API CALL
    def get_ip_info(self, ip_mode, ip):
        response = None
        if ip_mode == 'category': response = requests.get(url=self._ip_category_api.replace("{ip}", ip),
                                                          headers=self._headers)
        if ip_mode == 'report': response = requests.get(url=self._ip_report_api.replace("{ip}", ip),
                                                        headers=self._headers)
        if ip_mode == 'reputation': response = requests.get(url=self._ip_reputation_api.replace("{ip}", ip),
                                                            headers=self._headers)
        if ip_mode == 'malware': response = requests.get(url=self._ip_malware_api.replace("{ip}", ip),
                                                         headers=self._headers)
        if response.ok:
            return response.json()

        else:
            print(f'Status Code : {response.status_code} | Reason : {response.reason}')
            return None

    # -------------------------------------------------------------------------
    #   PROVIDE URL OR DOMAIN TO GET INFORMATION RELATED TO RESPSECTIVE API CALL
    # -------------------------------------------------------------------------
    def get_url_info(self, url_mode, url):
        response = None

        if url_mode == 'category': response = requests.get(url=self._url_category_api.replace("{url}", url),
                                                           headers=self._headers)
        if url_mode == 'history': response = requests.get(url=self._url_history_api.replace("{url}", url),
                                                          headers=self._headers)
        if url_mode == 'report': response = requests.get(url=self._url_report_api.replace("{url}", url),
                                                         headers=self._headers)
        if url_mode == 'malware': response = requests.get(url=self._url_malware_api.replace("{url}", url),
                                                          headers=self._headers)
        if response.ok:
            return response.json()
        else:
            print(f'Status Code : {response.status_code} | Reason : {response.reason}')
            return None

    # -------------------------------------------------------------------------
    #   PROVIDE FILE HASH OR MALWARE FAMILY NAME TO GET INFORMATION RELATED TO RESPSECTIVE API CALL
    # -------------------------------------------------------------------------
    def get_malware_info(self, malware_mode, entity):
        response = None
        # make a request to ibm using respective api call
        if malware_mode == 'filehash': response = requests.get(
            url=self._malware_family_api.replace("{filehash}", entity), headers=self._headers)
        if malware_mode == 'family': response = requests.get(
            url=self._malware_family_api.replace("{family_name}", entity), headers=self._headers)
        if response is not None:
            if response.status_code == 200:
                return response.json()  # returns json but parse data with customized information
            # If HTTP status code is not 200 then it will print status code and the reason behind it
            else:
                print(f'Status Code : {response.status_code} | Reason : {response.reason}')
                return None
        else:
            return None

    # -----------------------------------------------------------------------------------------
    #   PROVIDE IP ADDRESS (OR) URL (OR) DOMAIN (OR) FILE HASH TO GET INFORMATION FROM WHOIS
    # -----------------------------------------------------------------------------------------
    def get_whois_info(self, entity):
        """_summary_
        Args:
            entity (_type_): _description_
        Returns:
            _type_: _description_
        """
        response = requests.get(url=self._whois_api.replace("{host}", entity), headers=self._headers, timeout=60)
        if response.status_code == 200:
            return response.json()  # returns json but parse data with customized information
        # If HTTP status code is not 200 then it will print status code and the reason behind it
        else:
            print(f'Status Code : {response.status_code} | Reason : {response.reason}')
            return None


# ----------------------------------------------
#   INVOKE METHODS BY CREATING AN OBJECT
# ----------------------------------------------


def xforce_oop_entrypoint(domain: str, api_key: str, api_password: str) -> dict:
    ip = socket.gethostbyname(domain)

    result = []
    # create object for IBMXForce Class
    ibm = IBMXForce(api_key=api_key, api_password=api_password)

    for mode in ["category", "report", "reputation", "malware"]:
        # GET IP INFORMATION
        result.append(ibm.get_ip_info(ip_mode=mode, ip=ip))
        # GET URL OR DOMAIN INFORMATION
        result.append(ibm.get_url_info(url_mode=mode, url=domain))

    # # GET MALWARE INFORMATION
    # print(ibm.get_malware_info(malware_mode='filehash', entity='enter_file_hash'))
    # print(ibm.get_malware_info(malware_mode='family', entity='enter_family_name'))

    # GET WHOIS INFORMATION
    result.append(ibm.get_whois_info(entity=domain))
    return dict(error=None, response=result)


domain = "walla.co.il"
ap = "eefc9616-7f87-4290-9965-7ce53e22bbd3"
ap_pass = "4be25c9c-ffa3-40e3-8a9c-017ba332466a"
res = xforce_oop_entrypoint(domain, ap, ap_pass)
for k, v in res.items():
    print(k)
    print(v)
