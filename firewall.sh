#!/usr/bin/env bash

#############################
#  SETUP
#############################

# Define your hostname
HOSTNAME=52.166.134.91
SSHPORT=22

##################################
#securing TCP protocol parameters 
##################################

# Enable broadcast echo Protection
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Disable Source Routed Packets
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
echo 0 > /proc/sys/net/ipv4/conf/default/accept_source_route

# Enable TCP SYN Cookie Protection
echo 1 > /proc/sys/net/ipv4/tcp_syncookies


# Disable ICMP Redirect Acceptance
echo 0 > /proc/sys/net/ipv4/conf/default/accept_redirects

# Do not send Redirect Messages
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
echo 0 > /proc/sys/net/ipv4/conf/default/send_redirects

# Drop Spoofed Packets coming in on an interface, where responses
# would result in the reply going out a different interface.
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter

# Log packets with impossible addresses.
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians
echo 1 > /proc/sys/net/ipv4/conf/default/log_martians

# disable Explicit Congestion Notification
# too many routers are still ignorant
echo 0 > /proc/sys/net/ipv4/tcp_ecn


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
# Allow ssh for managment
# but secure from brute force 
#############################

#Disable brute force attack 
iptables -A INPUT -p tcp --dport $SSHPORT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport $SSHPORT -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j LOG --log-level 7 --log-prefix "Accept ssh port"
iptables -A INPUT -p tcp --dport $SSHPORT -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j ACCEPT
iptables -A INPUT -p tcp --dport $SSHPORT -j LOG --log-level 7 --log-prefix "Deny brute force on ssh port"    
iptables -A INPUT -p tcp --dport $SSHPORT -j DROP

#############################
#  ACCESS RULES
#############################

# Allow web server port 80       
/sbin/iptables -A INPUT -p tcp --dport 80 -j LOG --log-level 7 --log-prefix "Accept 80 HTTP"
/sbin/iptables -A INPUT -p tcp -d $HOSTNAME --dport 80 -j ACCEPT 

#Allow web server port 443

/sbin/iptables -A INPUT -p tcp --dport 443 -j LOG --log-level 7 --log-prefix "Accept 443 HTTP"
/sbin/iptables -A INPUT -p tcp -d $HOSTNAME --dport 443 -j ACCEPT 


#############################
#  DEFAULT DENY
#############################  

/sbin/iptables -A INPUT -d $HOSTNAME -j LOG --log-level 7 --log-prefix "Default Deny"
/sbin/iptables -A INPUT -j DROP 

