# eximrce

Simple python socket connection to test if exim is vulnerable to CVE-2019-10149. 
The payload simply touch a file in /root/lweximtest. Output will be slow
depending on server's reply and not knowing how to properly use python's socket module. Would love a lesson on how to speed it up. Only tested on cPanel boxes.

**Run locally on suspected server. This checks for indication of compromise.**
```
curl -s https://raw.githubusercontent.com/cowbe0x004/eximrce-CVE-2019-10149/master/eximioc.sh |bash
```

**Run remotely. Testing for remote code execution.**
```
git clone https://github.com/cowbe0x004/eximrce-CVE-2019-10149
cd eximrce-CVE-2019-10149
python eximrce.py <HOST> <PORT>
```
**If /root/lweximtest exists on the server, remote code execution is possible.**

**If you are not able to update exim, at least put this ACL in exim.conf so ${run{ can't be run.**

```
## change
	acl_smtp_rcpt = acl_smtp_rcpt
## to
	acl_smtp_rcpt = acl_check_rcpt

## after "begin acl"
acl_check_rcpt:
deny message = Restricted characters in address
domains = +local_domains
local_parts = ^[.] : ^.*[@%!/|] : ^.*\N\${run{\N.*}}

deny message = Restricted characters in address
domains = !+local_domains
local_parts = ^[./|] : ^.*[@%!] : ^.*/\\.\\./ : ^.*\N\${run{\N.*}}

accept
```
