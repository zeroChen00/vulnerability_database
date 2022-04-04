# laravel phpunit rce masscanner CVE-2017-9841
Masscanner for Laravel phpunit RCE **CVE-2017-9841**

## deps

```
python3 -m pip install -r requirements.txt

or 

pipenv install -r requirements.txt

```

# Usage

```

usage: tool [-h] [--file <hostnames.txt>] [--range <ip-start>,<ip-end>] [--single SINGLE]

optional arguments:
  -h, --help                   show this help message and exit
  --file <hostnames.txt>       Input your target host lists
  --range <ip-start>,<ip-end>  Set range IP Eg.: 192.168.15.1,192.168.15.100

```


# PoC
![poc.png](poc.png)

## Features
- Range of ips with --range Eg: python3 main.py --range 192.168.0.1,192.168.1.253
- List of hostnames --file Eg: python3 main.py --file hostnames.txt
- Dorks see dorks.txt

## References

[https://github.com/sebastianbergmann/phpunit/pull/1956](https://github.com/sebastianbergmann/phpunit/pull/1956)

[https://nvd.nist.gov/vuln/detail/CVE-2017-9841](https://nvd.nist.gov/vuln/detail/CVE-2017-9841)

## LOOK HERE

```
+------------------------------------------------------------------------------+
|  [!] Legal disclaimer: Usage of this tool for attacking                      |
|  targets without prior mutual consent is illegal.                            |
|  It is the end user's responsibility to obey all applicable                  | 
|  local, state and federal laws.                                              |
|  Developers assume no liability and are not responsible for any misuse or    |
|  damage caused by this program                                               |
+------------------------------------------------------------------------------+

```

Bye!

![tenor.gif](tenor.gif)
