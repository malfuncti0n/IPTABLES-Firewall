#!/bin/bash

#VARIABLE DEFINITION

#Define your hostname
HOSTNAME=52.166.134.91
#Define your SSH port
SSHPORT=22

#Define services needed , comma separated
SERVICES=80,443

##################################
#securing TCP protocol parameters# 
##################################

echo "securing TCP protocol parameters..."
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
echo "securing TCP protocol parameters...Done!"
echo -en '\n'
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


##############################
# Allow ssh for managment    #
# but secure from brute force# 
##############################

echo "Allowing SSH, disable Brute force Atack..."
echo -en '\n'
echo "adding rules for SSH on  port $SSHPORT"
echo -en '\n'
echo "iptables -A INPUT -p tcp --dport $SSHPORT -m state --state ESTABLISHED,RELATED -j ACCEPT"
iptables -A INPUT -p tcp --dport $SSHPORT -m state --state ESTABLISHED,RELATED -j ACCEPT
echo "iptables -A INPUT -p tcp --dport $SSHPORT -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j LOG --log-level 7 --log-prefix \"Accept ssh port\""
iptables -A INPUT -p tcp --dport $SSHPORT -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j LOG --log-level 7 --log-prefix "Accept ssh port"
echo "iptables -A INPUT -p tcp --dport $SSHPORT -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j ACCEPT"
iptables -A INPUT -p tcp --dport $SSHPORT -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j ACCEPT
echo "iptables -A INPUT -p tcp --dport $SSHPORT -j LOG --log-level 7 --log-prefix \"Deny brute force on ssh port\""
iptables -A INPUT -p tcp --dport $SSHPORT -j LOG --log-level 7 --log-prefix "Deny brute force on ssh port"   
echo "iptables -A INPUT -p tcp --dport $SSHPORT -j DROP" 
iptables -A INPUT -p tcp --dport $SSHPORT -j DROP

echo "Allowing SSH, disable Brute force Atack...Done!"
echo -en '\n'

######################################
#Access Rules, explode from services #
######################################

#first we explode port fror services
IFS=', ' read -r -a array <<< "$SERVICES"

#element is our port, one port per time.
for element in "${array[@]}"
do
    #for each service needed, we open firewall port.
    echo "adding rules for port $element"
    echo -en '\n'
    echo "/sbin/iptables -A INPUT -p tcp --dport $element -j LOG --log-level 7 --log-prefix \"Accept traffic to port $element\""
    /sbin/iptables -A INPUT -p tcp --dport $element -j LOG --log-level 7 --log-prefix "Accept traffic to port $element"
    echo "/sbin/iptables -A INPUT -p tcp -d $HOSTNAME --dport $element -j ACCEPT"
    /sbin/iptables -A INPUT -p tcp -d $HOSTNAME --dport $element -j ACCEPT
    echo -en '\n'
done



#############################
#Default deny               #
#############################  

/sbin/iptables -A INPUT -d $HOSTNAME -j LOG --log-level 7 --log-prefix "Default Deny"
/sbin/iptables -A INPUT -j DROP 


