This is a simple rootkit that will spawn a reverse bash shell when it receives a special ICMP packet.

It also hides itself from the module list (shown with lsmod) and sysfs.

A metasploit module is included for sending the special ICMP payload and receiving the reverse shell.
