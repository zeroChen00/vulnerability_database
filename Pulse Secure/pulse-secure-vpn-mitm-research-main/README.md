# pulse-secure-vpn-mitm-research
Pulse Secure mitm research 

## Release date
Joint release date with vendor: 26 Oct 2020

## Author
David Kierznowski, @withdk

## Credits
* Sahil Mahajan from the Pulse Secure PSIRT Team for support throughout the disclosure process.
* Alyssa Herrera, Justin Wagner, and Mimir, and Rich Warren for their write-up, "Red Teamer’s Guide to Pulse Secure SSL VPN" - Alyssa Herrera (4 September 2019).
* The SA Red Team for their ongoing support and encouragement.

## CVE Refs
* CVE-2020-8241 (8.1 High CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)
* CVE-2020-8239 (5.9 Medium CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N)

## Sample
<img src="https://raw.githubusercontent.com/withdk/pulse-secure-vpn-mitm-research/main/rogue-pulse-cmdhack-poc.gif" alt="A meterpreter reverse shell is spawned after user connects to rogue pulse server." />
Proof of concept demonstrating rogue-pulse-svr.py acquiring a reverse meterpreter shell from a Pulse Client connected to the same network.

## Introduction
Pulse Connect Secure (PCS) is a commonly used enterprise VPN solution. At the time of writing, PCS supports more than 20 million endpoints (Pulse Secure, n.d.). This research focused on reviewing the confidentiality and integrity of the network communication channel established between a Windows 10 PCS endpoint and a PCS gateway. In particular, it asks the question, "how secure is an endpoint when connected to an untrusted network?". This research applies to default and "Always-On" configurations.

### Impact (Medium - High)
When chained, it is possible to acquire remote code execution from an untrusted network with full SYSTEM privileges. Alternatively, an insider threat could use CVE-2020-8241 as a stand-alone vulnerability to escalate privileges. 

### Likelihood (Low - Medium)
These attacks could be used in a variety of situations, however, they are best suited to targeted attacks. Based on this and the assumptions below, the likelihood is low - medium.

### Potential Attacks
The following attacks have been successfully demonstrated in a proof-of-concept "rogue-pulse" tool:
* Steal user credentials. A rogue server could lure the user into revealing their login credentials.
* Execute binary from a Microsoft Windows UNC path. The PCS server supports the option to launch an executable following authentication. This can be abused to get code execution with the permissions of the logged on user. This builds on the work of Alyssa Herrera and team Alyssa Herrera (4 September 2019).
* Full remote administrator access by abusing host compliance checks. The host compliance checks are executed as SYSTEM. A rogue server could abuse this functionality to push down a malicious policy which allows arbitrary write access to the registry. 
* Intercept network traffic. This will allow the attacker to intercept and modify network traffic even when “always-on” is enabled. Currently the tool only displays network traffic requests from the endpoint.

*The PoC also implements an auto-login feature. This tricks the client into thinking it has previously authenticated. This would be useful in cases where code execution is the priority over credential harvesting.*

### Assumptions
* This research aims at acquiring remote code execution via an untrusted network. Both vulnerabilities are chained to achieve this objective. That said, an insider threat could simply use CVE-2020-8241 by itself to escalate privileges. 
* The PCS gateway is using the default configuration with "dynamic-trust" enabled. Note, the policy is usually updated and pushed down to the client after authentication. This means a small window of opportunity may still exist even after the gateway has disabled "dynanmic-trust".
* The attacker is in a position to man-in-the-middle HTTPS network traffic, e.g. the attacker has compromised a user's home network router, rogue Wi-Fi hotspots etc.
* The user is required to accept the certificate warning. One interesting observation is that the Pulse Secure Client will continue to pop up this message until the user accepts the certificate. In addition, the popup message is not particularly alarming. Finally, as a "Secure Client", a user is far more likely to ignore the message and connect anyway. This does not seem to be a big hurdle.
* The endpoint is connecting on a Microsoft Windows operating-system. 

## Recommendations 
In mitigating and remediating the issue the following recommendations should be considered:
* Organisations should conduct compliance against the Pulse Secure security best practises (Pulse Secure, 2 July 2019). Ensure that “Dynamic certificate trust” is disabled.
* Apply the vendor fixes (see https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44601).
* PCS Server script execution is executed as a child process of “Pulse.exe”. Thus, safeguards can be deployed by monitoring child processes of the “Pulse.exe” binary. 
* Monitor the “PulseSecureService” service for suspicious registry activity.

## References
* Pulse Secure (n.d.): Pulse Secure Unified Client [Online]. Available at https://www.pulsesecure.net/products/pulse-client/ (Accessed 1 June 2020)  
* Comodo (23 March 2011): Comodo SSL Affiliate The Recent RA Compromise. Available at https://blog.comodo.com/other/the-recent-ra-compromise/ (Accessed 9 June 2020)  
* Pulse Secure (2 July 2019): KB29805 - Pulse Connect Secure: Security configuration best practices. Available at https://kb.pulsesecure.net/articles/Pulse_Secure_Article/KB29805 (Accessed 9 June 2020)
* Alyssa Herrera (4 September 2019): Red Teamer’s Guide to Pulse Secure SSL VPN [Online]. Available at https://medium.com/bugbountywriteup/pulse-secure-ssl-vpn-post-auth-rce-to-ssh-shell-2b497d35c35b (Accessed 10 June 2020)
* The Internet Society (2004) RFC3748: Extensible Authentication Protocol (EAP) [Online]. Available at https://tools.ietf.org/html/rfc3748 (Accessed 10 June 2020)
https://github.com/gentilkiwi/mimikatz
* Catalin Cimpanu, ZDNet (26 March 2020): D-Link and Linksys routers hacked to point users to coronavirus-themed malware. https://www.zdnet.com/article/d-link-and-linksys-routers-hacked-to-point-users-to-coronavirus-themed-malware/
* Will Dormann, CERT/CC (02 January 2018): Pulse Secure Linux client GUI fails to validate SSL certificates. https://www.kb.cert.org/vuls/id/319904 (Accessed 10 June 2020).
* Pulse Secure (2015): SA40004 - [Pulse Secure] TLS connection verification issue (CVE-2015-5369). Available at https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA40004 (Accessed 9 June 2020)
* Pulse Secure (2009): SA40013 - TLS/SSL Renegotiation Vulnerability Pulse Connect Secure (PCS) (CVE-2009-3555) (Pulse Secure PSN-2009-11-573. Available at https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA40013 (Accessed 9 June 2020)
* Pulse Secure (2020): SA44426 - 2020-04: Out-of-Cycle Advisory: Multiple Host Checker Vulnerabilities. Available at https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44426. (Accessed 9 June 2020)
* Pulse Secure (2019b): SA44101 - 2019-04: Out-of-Cycle Advisory: Multiple vulnerabilities resolved in Pulse Connect Secure / Pulse Policy Secure 9.0RX. Available at https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101. (Accessed 9 June 2020)
* Dan Swinhoe, CSO (13 February 2019): What is a man-in-the-middle attack? How MitM attacks work and how to prevent them. Available at https://www.csoonline.com/article/3340117/what-is-a-man-in-the-middle-attack-how-mitm-attacks-work-and-how-to-prevent-them.html. (Accessed 9 June 2020)

## Disclaimer
The information provided is for educational and research purposes only. The author takes no responsibility for your use of this information and strongly condemns any attempt to violate applicable laws. The author undertakes no duty to update this information, provides no warranties to its completeness, use or applicability, and disclaims all reliance on it. Your use of this information is solely your responsibility.
