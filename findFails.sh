
#!/bin/bash
#this is an adition to firewall. it look inside auth.log for failed request and add the ips of more
#than "N" request in badips.db for ban.

grep "authentication failure" /var/log/auth.log* | grep rhost | sed -re 's/.*rhost=([^ ]+).*/\1/' | sort | uniq -c > tries

counter=1
for i in `cat tries | awk '{print $1}'`
do
if [ $i -ge 5 ]
then
#echo "#automaticly added from auth.log" >> badips.db
#cat tries | grep "$i" | awk '{print $2}' | sort | uniq
sed "${counter}q;d" tries | awk '{print $2}' 
counter=$((counter+1))
fi
done
