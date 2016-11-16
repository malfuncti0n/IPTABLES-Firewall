#!/bin/bash
#this is an adition to firewall. it look inside auth.log for failed request and add the ips of more
#than "N" request in badips.db for ban.

#if triggefirewall is 1 mean tha an ip added to badips.db so we need to reinitialize firewall.
triggerfirewall=0

#get all failed attemps
grep "authentication failure" /var/log/auth.log* | grep rhost | sed -re 's/.*rhost=([^ ]+).*/\1/' | sort | uniq -c > tries
numoffails=3
counter=1
for i in `cat tries | awk '{print $1}'`
do
#find which ip failed more than numoffails variable
if [ $i -ge $numoffails ]
then
tempip=`sed "${counter}q;d" tries | awk '{print $2}'` 
echo $tempip
#chech if ip is allready in badips.db if not we added and change the triggerfirewall to 1
        if grep -Fxq "$tempip" badips.db
        then
        echo "$tempip found in badips.db"
        else
        echo "$tempip not found, adding ip"
        echo "#automaticly ban from auth.log on $(date)" >> badips.db 
        echo "$tempip" >> badips.db
                if [ "$triggerfirewall" -eq "0" ]; then
                #make trigerfirewall 1 so firewall will reinitialize
                triggerfirewall=1
                fi
        fi
                
        

#
fi
counter=$((counter+1)) 
done

#check if we need to rerun firewall
if [ "$triggerfirewall" -eq 1 ]; then
path=`pwd`
echo "new ip(s) added in badips.db, reinicialize firewall"
echo "bash $path/firewall.sh" 
bash $path/firewall.sh
fi

