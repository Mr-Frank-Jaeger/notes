Metasploit Framework

Hacker methodology 
Recon
Exploitation
Persistence
Pillaging
Clean-off 

Starting Metasploit
----------------------------------------------------------------------
`postgresql`
ensure pastgresql is enable for metasploit

`systemctl enable postgresqli`
will make it so postgresql auto starts on boot

`service postgresql [status, start, stop]`
To do it manually

`msfdb init`
start the metasplit database

`msfconsole`
To start metas-loot

`db_status`
shows that you are connected to postgresql

`Help`
for the man pages

`Search tomcat`
show you the modules

`Info [module name]`
give info on that module

``[command] -h`
info on a command

`Search tomcat type: [auxilliary, exploit, or post]`
will show just those modules

`workspace`
to see the are you are working, don’t work in the default make your own

`workspace -a [name it]`
so if it gets fucked up you don’t have to rebuild metasploit

searching in Metasploit
----------------------------------------------------------------------
spool
to write to file

search [module name]

Info [module full name]
shows lots of info on the mod

Search platform: “[OS]” type:[aux, vul, or mod]      to see all the mod for that OS type
db_rebuild_cache      rebuilds modular database case
load -l       will show the plugins
db_import    Import scan results
With a mod loaded
show advanced, to see the settings and then, set verbose true
Kill   to kill a process
show options       to see options for a mods
set timestampOutput true     For timestamps  
show nops            
show encoders
host      for default info on scan reports
Services -u    to see what services that are up
handler -H [ip] -P [port] -p [payload]

Passive Recon - no active engagement of the tgt
----------------------------------------------------------------------
	Netcraft, centralops.net , iputils, whois, dig, recon-ng, nslookup, job boards, 		social media, https://inteltechniques.com/menu.html, traceroute command (round trip times 2-557ms oceanic crossing (uses a lot of airports), 500ms or above are sat hops, recon-ng command is like metaslpoit that scraps the internet - use APIs so google don’t flag you as a bot, theharvester command scans sites to for info on them, shoran.io 

Active recon - engages with the tgt system such as using port scanners
----------------------------------------------------------------------
	map, port scanners, auxiliary modules, vulnerability scanners
Net discover -r [ip]/[cidr] > file.txt     to save output to a file

Id live hosts
#!/bin/bash
for ip in $(seq 1 254); do
Ping -c 10.10.10.$ip |grep “bytes from” |cut “:” -f1 &
done
 
Live hosts in map
#!/bin/bash
$ nmap -sn -T4 -oG Discovery.gnmap [ip] [cidr]
$ grep “Status: Up” Discover.gnmap |cut -f 2 -d ‘ ‘ > livehosts.txt
Banner garbing - banners have info on services
	telnet [ip] [port]
	curl -s -I [ip] | grep -e “Server: “
	nc -v [ip] [port]
	nmap -Pn -p [port] -sV —script=banner [ip]
	p0f -i [nic] -p -o /output/file/location/file.log


Using nmap and metasploit
----------------------------------------------------------------------
Do a scan and save it to a file then open it in metasploit

Nmap -oX [file]      saves nmapscan to file type   
msfdb init        start the metasplit database
msfconsole      To start metasploit console

db_import [nmapscan]
hosts		shows hosts from scan
services	shows services on hosts
db_export -f xml [file]		to export database form metasploit
search [namesish]	to find modules
use [moduale]		then it will be added to the prompt
set [parameters]
run		while in a module to use the module
host [ip]	to only select a single ip
hosts -r 	to set module on all hosts in database
exploit found [+] green

nmap scanning strategy 
#host disc and generate live hosts
nmap -sn -T4 -oG Discovery.gnmap [ip]/[cidr]
grep "Status: Up" Discovery.gnmap | cut -f 2 -d ' ' > LiveHosts.txt

# port disc - most common ports
namp -sS -T4 -Pn -oG TopTCP -iL LiveHosts.txt
namp -sU -T4 -Pn -oN TopUDP -iL LiveHosts.txt



SMB (samba enumeration) used in corp network for filesharing
----------------------------------------------------------------------
enum4linux [ip]		to find info about a box, it is loud

Review
Nmap quiet -T (number of packets per sec)
Tool other than nmap - p0f
add/enable in meta to increase functionality - plugins
Start meta, check - service Postgres start

#show nmap in html
nmap -Pn -v -T4 -A -iL lab1.txt -oX lab1.xml; xsltproc lab1.xml; -o lab.html

#lhost
    * can be set to your ip or the interface you are using for network access
    * such as `eth0`

#sessions
    `sessions`   list all sessions
    `-i <session number>`   to switch to that session
    
#meterpreter shell
https://www.getastra.com/blog/security-audit/meterpreter-commands-post-exploitation/
`upload`
    lets you upload an exploit or file from attacker mech to victum
    
`sysinfo`
    get info about the system
    
`getuid`
    gets you info about current logged in user and its pris
    
`getpid`
    see current process, you should know this for priv escalation
    
`ps`
    see all processes
    
`migrate`
    to move from one process to another
    `run migrate -h` will list all processes we CAN move too
    `run migrate -p 157` moves to process 157
   
`getsystem`
    will run a few well known priv escalations to try and get better privs
    
`hashdump`
    dumps all users hashed passwords
    
`shell`
    will dump us in a standard windows shell
    
`search`
    will search thru victims files system for files
    
`clearev`
    clears all windows xp logs
    
`sysinfo`
    gives us all the system info about victim
    
#pivoting
https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html
    

    
   
    
