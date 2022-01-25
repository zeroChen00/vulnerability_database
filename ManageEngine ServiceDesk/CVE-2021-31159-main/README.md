# Zoho ManageEngine ServiceDesk Plus MSP - Active Directory User Enumeration (CVE-2021-31159)

This script takes advantage of ServiceDesk Plus before build 10519 having different output in the password recovery functionality: if the user exists it returns a message claiming an email has been sent but if it does not exist the message is always the same. 

Knowing this it is possible to enumerate accounts in the application or, what we will try to exploit with this script, accounts of an Active Directory if AD authentication is enabled. Very useful when the application is open to the internet and the format of the AD user accounts (for example, name initial + surname) is known.

```
python3 exploit.py -t TARGET_URL -d DOMAIN -u USERSFILE [-o OUTPUTFILE]
```  
