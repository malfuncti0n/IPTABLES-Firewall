#!/bin/bash


#step 0, variable definition

#find your local ip 
localip=`ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'`

#Define your SSH port
sshport=22

#Define services needed , comma separated
services=80,443,53
udpservices=
#file with ips to ban
badips=badips.db
ips=`cat $badips | egrep -v "^#|^$"`

# Die if file not found
[ ! -f "$badips" ] && { echo "$0: File $badips not found."; exit 1; }


#step 1, securing TCP protocol


echo "step 1, securing TCP protocol..."
echo -en '\n'
# Enable broadcast echo Protection
echo "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Disable Source Routed Packets
echo "echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route"
echo "echo 0 > /proc/sys/net/ipv4/conf/default/accept_source_route"
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
echo 0 > /proc/sys/net/ipv4/conf/default/accept_source_route

# Enable TCP SYN Cookie Protection
echo "echo 1 > /proc/sys/net/ipv4/tcp_syncookies"
echo 1 > /proc/sys/net/ipv4/tcp_syncookies


# Disable ICMP Redirect Acceptance
echo "echo 0 > /proc/sys/net/ipv4/conf/default/accept_redirects"
echo 0 > /proc/sys/net/ipv4/conf/default/accept_redirects

# Do not send Redirect Messages
echo "echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects"
echo "echo 0 > /proc/sys/net/ipv4/conf/default/send_redirects"
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
echo 0 > /proc/sys/net/ipv4/conf/default/send_redirects

# Drop Spoofed Packets coming in on an interface, where responses
# would result in the reply going out a different interface.
echo "echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter"
echo "echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter"
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter

# Log packets with impossible addresses.
echo "echo 1 > /proc/sys/net/ipv4/conf/all/log_martians"
echo "echo 1 > /proc/sys/net/ipv4/conf/default/log_martians"
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians
echo 1 > /proc/sys/net/ipv4/conf/default/log_martians

# disable Explicit Congestion Notification
# too many routers are still ignorant
echo "echo 0 > /proc/sys/net/ipv4/tcp_ecn"
echo 0 > /proc/sys/net/ipv4/tcp_ecn


echo -en '\n'
echo "step 1, securing TCP protocol...Done!"
echo -en '\n'

#step 2, create firewall rules
echo "step 2, create firewall rules..."

# Clear all rules
/sbin/iptables -F

# Don't forward traffic
/sbin/iptables -P FORWARD DROP 

# Allow outgoing traffic
/sbin/iptables -P OUTPUT ACCEPT

# Allow established traffic
/sbin/iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 

# Allow localhost traffic
/sbin/iptables -A INPUT -i lo -j ACCEPT


#############################
#create new chain for badips#
#############################

/sbin/iptables  -N droplist


# Filter out comments and blank lines
# store each ip or subnet in $ip
## Ban Ips
for banip in $ips; do
        # Append everything to droplist
	echo "/sbin/iptables -A droplist -s $banip -j LOG --log-level 7  --log-prefix \"Drop Bad IP List\""
	/sbin/iptables -A droplist -s $banip -j LOG --log-level 7  --log-prefix "Drop Bad IP List"
	echo "/sbin/iptables -A droplist -s $banip  -j DROP"
	/sbin/iptables -A droplist -s $banip -j DROP
done

# Finally, insert or append our black list 
echo "/sbin/iptables -I INPUT -j droplist"
/sbin/iptables -I INPUT -j droplist
echo "/sbin/iptables -I OUTPUT -j droplist"
/sbin/iptables -I OUTPUT -j droplist
echo "/sbin/iptables -I FORWARD -j droplist"
/sbin/iptables -I FORWARD -j droplist



##############################
# Allow ssh for managment    #
# but secure from brute force# 
##############################

echo "Allowing SSH, disable Brute force Atack..."
echo -en '\n'
echo "adding rules for SSH on  port $sshport"
echo -en '\n'
echo "iptables -A INPUT -p tcp --dport $sshport -m state --state ESTABLISHED,RELATED -j ACCEPT"
iptables -A INPUT -p tcp --dport $sshport -m state --state ESTABLISHED,RELATED -j ACCEPT
echo "iptables -A INPUT -p tcp --dport $sshport -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j LOG --log-level 7 --log-prefix \"Accept ssh port\""
iptables -A INPUT -p tcp --dport $sshport -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j LOG --log-level 7 --log-prefix "Accept ssh port"
echo "iptables -A INPUT -p tcp --dport $sshport -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j ACCEPT"
iptables -A INPUT -p tcp --dport $sshport -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j ACCEPT
echo "iptables -A INPUT -p tcp --dport $sshport -j LOG --log-level 7 --log-prefix \"Deny brute force on ssh port\""
iptables -A INPUT -p tcp --dport $sshport -j LOG --log-level 7 --log-prefix "Deny brute force on ssh port"   
echo "iptables -A INPUT -p tcp --dport $sshport -j DROP" 
iptables -A INPUT -p tcp --dport $sshport -j DROP

echo "Allowing SSH, disable Brute force Atack...Done!"
echo -en '\n'

######################################
#Access Rules, explode from services #
######################################
#tcp rules
#first we explode port fror services
IFS=', ' read -r -a array <<< "$services"

#element is our port, one port per time.
for element in "${array[@]}"
do
    #for each service needed, we open firewall port.
    echo "adding rules for port $element"
    echo -en '\n'
    echo "/sbin/iptables -A INPUT -p tcp --dport $element -j LOG --log-level 7 --log-prefix \"Accept traffic to port $element\""
    /sbin/iptables -A INPUT -p tcp --dport $element -j LOG --log-level 7 --log-prefix "Accept traffic to port $element"
    echo "/sbin/iptables -A INPUT -p tcp -d $localip --dport $element -j ACCEPT"
    /sbin/iptables -A INPUT -p tcp -d $localip --dport $element -j ACCEPT
    echo -en '\n'
done

#udprules

IFS=', ' read -r -a array <<< "$udpservices"

#element is our port, one port per time.
for element in "${array[@]}"
do
    #for each service needed, we open firewall port.
    echo "adding rules for port $element"
    echo -en '\n'
    echo "/sbin/iptables -A INPUT -p udp --dport $element -j LOG --log-level 7 --log-prefix \"Accept traffic to port $element\""
    /sbin/iptables -A INPUT -p udp --dport $element -j LOG --log-level 7 --log-prefix "Accept traffic to port $element"
    echo "/sbin/iptables -A INPUT -p udp -d $localip --dport $element -j ACCEPT"
    /sbin/iptables -A INPUT -p udp -d $localip --dport $element -j ACCEPT
    echo -en '\n'
done

#############################
#Default deny               #
#############################  

/sbin/iptables -A INPUT -d $localip -j LOG --log-level 7 --log-prefix "Default Deny"
/sbin/iptables -A INPUT -j DROP 

echo "Firewall is ready, you are now protected!"
