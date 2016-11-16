# linux-firewall

Linux Firewall base on IPTABLES with TCP hardening. firewall.sh ban all ip on badips.db and hardering tcp.
findFails check in auth.log and add multiple failed request in badips.db if it found new ip, it is reinitialize firewall.

How to use:
  on firewall.sh:
  Add your ssh port on sshport variable.
  Add tcp ports on services variable, comma seperated.
  Add udp ports on udpservices variable, comma seperated.
  add it in rc.local for execution from boot.
  run it!
  
  on findFails.sh
  add it on cronjon
