groupenum
=========

This repository hosts some useful scripts for enumerating VPN group names or IDs.

groupenum.sh:

Shell script to enumerate group names from vulnerable Cisco devices by the presence of the Dead Peer Detection payload in the response. See Cisco reference: http://www.cisco.com/en/US/products/csr/cisco-sr-20101124-vpn-grpname.html
The script uses ike-scan http://www.nta-monitor.com/tools-resources/security-tools/ike-scan

groupenum.py

This Python POC enumerates group names from Cisco devices by differing responses to IKE negotiations. See https://www.trustwave.com/spiderlabs/advisories/TWSL2013-004.txt.


Further details and a guide can be found here:
http://blog.spiderlabs.com/2013/03/cracking-ike-aggressive-mode-hashes-part-1.html
