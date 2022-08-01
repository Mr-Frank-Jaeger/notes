CTF Cheatsheet
================================================================================
https://crontab.guru/
    cron tab cheat sheet that is interactive
    
https://explainshell.com/
    breaks down commands with man explains

================================================================================
`--`
    add to any command to tell it you are no longer adding flags
    useful with files that start with `-` such as `-file.04`

`unrar`
    open rar archive
    
`tar -<flags> <tarballname.tar> <files or dir to compress>`
    `-cf` compresses file into tar ball
    `-xf` extracts file into tar ball
    `-v` verbosity
    `-j` bzip2
    `-z` gunzip
`gzip -d <file.gz>`
    decompress a gunzip file
`bzip2 -d <file.bz2>`
    decompress a bzip2 file
    
`locate <file>`
    locate a file
    `updatedb` will update db for locate
    # must be installed with `apt install mlocate`

`find . -size 512c`
    uses find to look for a file that is 512 bytes large
    https://www.tecmint.com/35-practical-examples-of-linux-find-command/
    `find / -type f -size +50M -exec du -h {} \; | sort -n`
        will find files bigger than 50Mbs and sort them
    `-iname` case insensitive
    
`which <cmd>`
    tells you where that cmd is called from
        
`exiftool`
    see metadata for an image. `-r -ext` to see meta for all in dir
    
`xxd`     
    see binary 
    `binary_file to_hex_file`
    `-r -p hex_file to_binary_file`
    
`nmcli device show <interface>`
    checks status of a device
    
`script -a /a/place/to/store/<name>`
    will run script in ur term and copy all commands and results

`base 64`
    -d decode, -i input.file (-i encode if only flag)
    
`chmod`
    change permissions
    `666` wr for all
    `755` rwx for owner, rx for group and others
   `777` rwx for all

# process management
----------------------------------------------------------------------
`ps`
    display all current active processes in PID
    `kill <PID>` kills process id
    `killall <process>` kills all process with that name
    
`bg`
    list stopped or backgrounded jobs; resumes a stopped background job
`fg`
    brings most recent job to foreground
    `a` brings job to forground
   
`Ctrl+Z`
    stopped current command, resume with `fg` or `bg`
    
`jobs`
    list all jobs running
    
    
    
`grep what where.txt`      
   `-Ril` -R recursive, -i ignores case, -l only shows files that match 
   `-E "term1|term2|term3"` will search for all 3 terms
   
`cut`
    `-d '.'` delimiter of fields in this case `.`
    `-f 3-5` cut out all but fields 3,4,5
    
`sort file.txt | uniq -u`
    -u only displays unique lines
    
`rev`
    reverse each line of input horizontally but keep line order
    vertically
    
`tac`
    will `cat` a file in reverse line order but keeps charater order
    horizontally
    
`strings -n length file.txt`    
    only displays human readable strings of -n length
    
`tr [a-z] [n-za-m]`
    piped input will change letters of first set to match 2nd set (13 places)
    [A-Z] will do the same for capital letters
    
`upx -d` 
    to unpack a upx packed file

`mkdir`
    make dir
    `-p` make dir and sub dirs
    
`rdesktop <ip> -u [username] -p [password] -g [window size WxH] 1024x768 -x [RDP5] 0x80`
    rdp from linux to windows
`rdesktop <ip> -g 1024x768`
    rdp from linux to linux

`ssh user@ipaddress -p 4434 ls`
    will connect via ssh and run a `ls` cmd on remote

`youtube-dl`
    installed by brew to download youtube videos

`binwalt`
    runs `file` over and over to find nested files
    `-e *` extracts the file and `*` does it to all possiple files
    `-E` checks the entropy of the file. higher the entropy the more
        likly that its encrpted with somthing

`file`    
    get info about a file type
    
CyberChef - https://gchq.github.io/CyberChef/
    easy tool for changing files
    
`tldr`
    gives your cmd examples
    
`\`charater 
    escapes character when put in front of it
    sometimes you need to use absolute path with weird file names like `-`
`./`
    used to run scripts but also will help when access files such as `-`
    tells term to access somthing in current path
    
    
`2>/dev/null`
    dumps all errors so they don't see them in the term output
    
`hURL`
    hex, rot13, ect encoder and decoder
    
`mktemp`
    creates a temp file in /etc/tmp/ and returns the path to the file
    `myfile="$(mktemp)"`
    `cd "$(mktemp -d)"`     makes a temp directory
    
`openssl s_client -connect localhost:30001 -ign_eof`
    connect to localhost on port 30001, -ign_eof ignore end of file otherwise
    client will disconnect when it runs out of input
    
`^this^that` 
    in bash, will run perious cmd and sub this for that
    
`ssh user@ip sh`
    will log into user and bypass bash and just give u a shell
    can sub `sh` with any other command you want it to run

`job contorl`
    `&` at the end of a command will run it in the background and display its job
    number
    `Ctrl+z` background and stop a program
    `jobs` show all jobs
    `bg %4` will backgournd job 4 and run it
    `fg %9` will bring job 9 to the fore ground and run

`mktemp -d`
    to make a temp dir or remove -d for file
    
`escape a shell`
    any interactive commands (`pagers, editors, shells, langs`)
    like `more, less, vi,`
    
`ltrace ./an_exicutable`
    runs an_exicutable and prints all dynamic library calls so you can 
    see what the program is doing. things to look for:
        `strcmp` compares strings used for password checking
        `access()` checks permissions based on owner not `whoami`
        `fopen()` opens a file 

`strace`
    shows all the system calls for a program
    
`ss`
    replaces `netstat` (deprocated) with more info
    `-t` tcp ports
    `-u` udp ports
    `-l` listening ports
    `-n` port number
    `-p` process/program name
    
`watch`
    put infront of a cmd to see in real time
    
`tail` 
    to see last 10 lines of a file
    `-f` to see the last 10 lines in real time
`wc`
    to see number of words
    `-l` to see number of lines
`top`
    see processes running by resources usage

#wipe all logs
    `du -h /var/log`    to see size of all log files
    `cat /dev/null > *.log` will empty all logs but keep their filenames
    `history -c` to clear history
    https://linuxhint.com/delete-history-linux/
    * by adding a space before all commands in cli, they won't be added to
      history

`dmesg`
    see messeges stored in ring buffer (events between boot and startup
    processes)
    `-H` timestamp in nanosec from kernal boot
    `-T` human readable timestamps
    `--follow` watch in realtime
    `dmesg | grep -i "term"` to search for case insensitive search
    
`journalctl`
    read and filter system log messeges
    `-f` follow the journal and see logs as they appear
    `-S "2020-91-12 07:00:00"` see logs SINCE date and time
    `-S -1d` since one day / in the last day
    `-S -1h` since one hour / in the last hour
    `--vacuum-time=1days` removes all logs older than 1 day
    https://www.howtogeek.com/499623/how-to-use-journalctl-to-read-linux-system-logs/
`/var/log` dir for all linux logs

`traceroute`
    check route to a destination
    
`systemctl`
    manages services `status`, `enable`, `disable`
    
`lsof [option] [user name]`
    "list of open file" shows all files that are open by a processes
    `-u darrow` lists all files open by darrow
    `-u ^darrow` list all files open EXCEPT for by darrow
    `-c` list all files open by a process -c processname
    `-p` by process ID
    https://www.geeksforgeeks.org/lsof-command-in-linux-with-examples/
    
`chroot`
    change the root dir for testing or password recovery or new bootloader
    
`ipconfig /release`
    drops ip address on Windows
`ipconfig /renew`
    renews dhcp from dhcp server on Windows
    
# reset root password with GRUB
https://www.freecodecamp.org/news/how-to-recover-your-lost-root-password-in-centos/
    
#setting ips and gateways with terminal Debian
https://bytefreaks.net/gnulinux/how-to-set-a-static-ip-address-from-the-command-line-in-gnulinux-using-ifconfig-and-route?amp=1
* non-persistent
    `sudo ifconfig eth0 192.168.1.115 netmask 255.255.255.0;`
    `sudo route add default gw 192.168.1.1 eth0;`
* persistent
https://www.cyberciti.biz/faq/add-configure-set-up-static-ip-address-on-debianlinux/
    * edit `/etc/network/interfaces` and add
    ```
    auto eth0
        iface eth0 inet static
        address 192.168.1.101
        netmask 255.255.255.0
        gateway 192.168.1.1
        dns-nameservers 8.8.8.8 9.9.9.9
    ```
    * then restart NetworkManager
    * then bring the interface down and up
        `ifdown eth0`
        `ifup eth0`

#setting ips, gateways, and nameservers(DNS) with ubuntu
https://ubuntu.com/server/docs/network-configuration
* persistant - edit `/etc/netplan/00_config.yaml` then `sudo netplan apply` to take effect
* non-persistant for nameservers edit `/etc/resolv.conf`

#setting static routes with windows
* tmp
`route add 192.168.2.0 mask 255.255.255.0 192.168.2.1`
* persistant
`route -p add 192.168.2.0 mask 255.255.255.0 192.168.2.1`
* check routes
`route print`

#mounting a network share drive
https://markontech.com/linux/mount-a-network-shared-drive-on-linux/
* if there is a share drive/folder on the network you can mount it in linux
    `mkdir /mnt/share`
    `mount -o username=<user> //<ip>/location/of/share /mnt/share`
        * for windows smb default <ip>/here assumes its already in Temp
    * now you can cd into `/mnt/share` on linux and access the share over smb
    * can check to see if a share is up
        `smbclient -U <user> -L \\\\<ip>\\`
* samba for linux
https://ubuntu.com/tutorials/install-and-configure-samba#3-setting-up-samba

#enabling ivp4 forwarding
https://lunux.net/centos-7-how-to-enable-ip-forwarding/
/etc/sysctl.conf:
`/sbin/sysctl -p` 
    check ipv4 on `1` or off `0`
`net.ipv4.ip_forward = 1`
    sets the box to forward IP traffic so u can use it as a pivot
    edit `/etc/sysctl.conf` to make persistent. uncomment line
    `#net.ipv4.ip_forward = 1` then run `sysctl -p`
    # if this line isn't here ADD it

#crontab
https://crontab.guru/
`crontab -e`
    edit the crontab (keep blank line at end!!!)
`sudo cron -u root -e`
    edit root's cron tab
    * will run every 1 min
    `*/1 * * * * echo $(date) | sudo tee -a /somewhere/that/needs/root`
`crontab -l`
    list crontab 
    `@reboot /path/to/script.sh` runs at reboot
    
    * * * * *
	minute (0-59), hour (0-23), day of month(1-31), month (1-12), day of week (1-7)
    
	* Defines all scheduling parameters
	, Have 2 or more execution times of a single command
	- Determine a range of time when setting multiple execution times of a single command
	/ Create predetermined intervals of time in a specific range
	L Determine the last day of a week in a given month. 2L means the last Tuesday of the month
	W Determine the closest weekday of a given time. 1W means if the 1st is a Saturday execute on Monday which would be the 3rd
	# For determining the day of the week followed by which week in the month it should be executed. 3#2 means the second wednesday
	? Leave it blank 
    
* to check your public ip
`curl icanhazip.com`

* see all enabled services
    `ls /etc/systemd/system/multi-user.target.wants`
* see all services and status
    `systemctl status`
    
* in vim if you forgot sudo: `:w ! sudo tee %`

* search man files for descriptions if you don't know what cmd u need
    `apropos <somthing you want to do>`
* check aliases in the ENV
    `alias`
    * if you remove an alias from `.bashrc` you need to relaunch term to load
      or: `unalias <alias name>`
      * you need to run `unalias` and remove it form `.bashrc`
      * 


#Easy Nmap scans
----------------------------------------------------------------------
`nmap <flags> <ip>`
    `-O` OS detection
    `-sV` service detection on ports
    `-p-` all ports
    `-T4` speed from 1 to 5
    `192.168.50.0/24` will scan whole network
    
# adding backdoor users into windows
----------------------------------------------------------------------
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v=ws.11)
* create user
    `net user <username> <password> /add /active:yes`
* add user to admin group
    `net localgroup administrators <username> /add`
* you may need to give yourself permission on a folder for dll exploits/overwrites
    `icacls c:\Windows\What\Ever /grant <username>:(OI)(CI)F /t`

centos - disable firewallD and then iptables will be the only firewall
`sudo systemclt stop firewalld`
`sudo systemclt disable firewalld`

