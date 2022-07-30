Roka Security OpenVPN 2.4
https://learn.rokasecurity.com/
https://tmuxcheatsheet.com/

* run a command from a remote box via ssh
`ssh <boxname> 'curl -s icanhazip.com'`
    change to `ssh -t` if you need to run as sudo so u get an interactive box
    * this checks the ip off a website from the remote box

* ssh ProxyJump from cmd line: ssh from me to 1 to 2 to 3
   `ssh -J <box1> <box2> <box3>`
   
* check the ssh ips: local is box, peer is where the ssh connection is from
    `ss -ptna`

* to prevent history from working add a space before you command


#.ssh/config
----------------------------------------------------------------------
* at the top of the config this will ensure that ONLY its key is used. This
    will prevent sending a key to the wrong box to prevent spillage
`Host *`
    `IdentitiesOnly yes`
    
* you can make more configs and to have them seen by the main config add
    to the top
`Include ~/.ssh/path/to/addional_config`

#IP tables
----------------------------------------------------------------------
 
#OpenVPN
----------------------------------------------------------------------
* create config fie `/etc/openvpn/myconfig.config`
    [myconfig](myconfig)
    
* start service, use `enable` for persistance
    `systemctl start openvpn@myconfig`
    
    * can check for port `1194` to be sure its up
        `sudo ss -puna | grep openvpn`
    
    * clients/servers will create a new interface called `tun0`
* if errors, you can force load a config
    `openvpn --config /ect/openvpn/myconfig.conf`
    * if it hangs then config is good
    * if don't hang, the config is borked
    * sometimes if borked log will not log

#Wireguard
----------------------------------------------------------------------
`sudo apt install wireguard -y`
`sudo touch /etc/wireguard/wg0.conf`
`sudo chmod 600 /etc/wireguard/wg0.conf`

#gen keys
`wg genkey | tee private.key | wg pubkey | tee public.key`
# `tee` takes standard input and sends it to standard out and a file
    * `-a` means append to end of file
`cat private.key | sudo tee -a /etc/wireguard/wg0.conf`

#then edit the wg0.conf 
* `SaveConfig = true` will auto add new clients after
    the first one after they connect and add them to the wg0.conf file
   [server_wg0_conf](server_wg0_conf)
   [client_wg0_conf](client_wg0_conf)

#can test with
`wg-quick up wg0`
`sudo ss -puna | grep 51820`

#on server side to add a client (wg0 must be up on server)
`sudo wg set wg0 peer <client public key> allowed-ips 10.x.2.2/32`
#save this change to server config
`sudo wg-quick save wg0`
#bring both down and back up and you should be good

#set persistence `sudo systemctl enable wg-quick@wg0`

#troubleshooting, no real logging so use debugging
`echo 'module wireguard +p' | sudo tee /sys/kernel/debug/dynamic_debug/control`
* then you can use `dmesg` or see the `journalctl` in realtime
    `dmesg | grep wireguard`
    `sudo journalctl -f | grep wireguard`
* turn off debugging
    `echo 'module wireguard -p' | sudo tee /sys/kernel/debug/dynamic_debug/control`
    
* subnet wireguard
    * change server to `/24` for multiple clients
    
    * need to turn on ipv4 forwarding so clients can talk out of server to non
      clients
    * turn on ip forwarding edit `/etc/sysctl.conf`
    * uncomment the line `net.ipv4.ip_forward = 1`
    * reload conf with `sudo sysctl -p`
    
    * client stays the same, ensure `Address = <ip>/32` and 
      under [Peer] `AllowedIPs = <ip>/24`
      
    * `wg-quick up wg0` on both server and client
    * on server add the client
        `sudo wg set wg0 peer <client pub key> allowed-ips <client ip/32>`
        * ping from server to client to be sure your good
        `wg-quick save wg0`
        
    
#Discrete (encrypted) PKI certs and creating a cert auth
----------------------------------------------------------------------
* git clone easy-rsa in `/opt/`
    `sudo git clone https://github.com/OpenVPN/easy-rsa.git`
* change permission so you don't have to use sudo
    `sudo chown <user>:<user> easy-rsa -R`
    
* build the CA
    `./easyrsa build-server-full forest-server nopass inline`
    `cd /opt/easyrsa/easyrsa3`
    
    * initialize for a CA
        `./easyrsa init-pki`

    `./easyrsa --batch --req-cn="<name>" build-ca`
    
    * to check it go to `/pki` dir and run
        `openssl x509 -text -in ca.crt | grep -i "cn"`
    
* build server pub/pri keys
    `cd /opt/easyrsa/easyrsa3`
    `./easyrsa build-server-full <name>-server nopass`

* build client pub/pri keys
    `./easyrsa build-client-full <name>-client nopass`

* make a new file and add your conf settings called `<name>-client.directives`
* take a new `ta.key` if you are using tls auth to encrypted the handshake
    `openvpn --genkey --secret ta.key`
    * add the html tags at top and bottom
* then create `.conf` file
    `cat <name>-client.directives <name>client.creds ta.key > <name>-client.conf`
    # for server and client!!!
    
* place them in their own dirs and tar them to transfer them
    * should have 2x`.crt` 3x`.key`
    * run from in dir with all files you want to tar ball
    `tar cvf <name>-client.tar *` 

* use `scp -3` to 3rd party scp (remote to remote thru me)
* you need your `.ssh/config` set up to make this easyer
    `scp -3 <remote1>:/tmp/<name>-server.tar <remote2ps>:/tmp/`
    `scp -3 <remote1>:/tmp/<name>-client.tar <remote2pc>:/tmp/`
    
* on each of your mechines move the tar to `/etc/openvpn` and extract
    `tar xvf <name-server or client>.tar`
    
* change permissions to root
    `sudo chown root:root <name>*`

* edit the `.conf` files for each to use the certs
    [name server conf](name-server-conf)
    [name client conf](name-client-conf)

* bring them up and ping
    `sudo systemctl start openvpn@<name>-<server or client>`
    
#inline PKI certs

* git clone easyrsa, change permissions, initalize, and build CA like above

* create keys in `/pki/` dir
    `./easyrsa build-server-full forest-server nopass inline`
    `./easyrsa build-client-full forest-client nopass inline`

* turn `.creds` file into openvpn config file then move to hosts
* you can edit the top of the `.creds` file and save it as `<name-server or client>.conf`
* then just `scp` the new `.conf` files to client and servers. example:
    [name server conf inline](name-server-conf-inline)
    * #omitted will be filled with large keys!

#Subnet OpenVPN
----------------------------------------------------------------------
* just change the config files for server and clients
    * server
        `topology subnet`
        `server <10.0.0.0> <255.255.255.0>`
    * client
        remove the `ifconfg` line
        
#Hardening: basic
----------------------------------------------------------------------
# all on server unless other wise said
* on linux (not windows) can change the name of the interface in the 
  <name>server.conf. we want it to be called `mwr0`
    `dev-type tun`
    `dev mwr0`
    * add `verb 4` for more verbosity in logs
    * add `fast-io` will speed up connection speed for Win and linux not android
    * for obscurity change the port by adding: to look like other traffic
        `port 443`
        `proto tcp-server`
        * if you do this you need to add it to the clients aswell !!!
        * check the new port with `lsof -Pni`
    * change the data channel cipher from default AES-256-GCM
        `ncp-ciphers AES-128-GCM:AES-128-CBC` on server
        `ciphers AES-128-GCM` on client
        * server will ONLY accept thouse 2 and will alwasy pick the higher
            * this prevents downgrade attacks from mal clients
        * client will request that encryption but will take what the server gives me
    * HMAC will give digital sig for each messege but the default SHA128 is
          broken so we need to change it by adding
          `auth SHA256`
    # most important to do!!!!!!!!!!!
    * Shared Key Auth to prevent mal clients - encrypted handshake!
    * stops common names from going out over clear
        `openvpn --genkey --secret ta.key` in home dir
        * server and client both need a copy, add that key to the end of each
          config file with HTML tags around it. This will encrypted the
          handshake
          `<tls-crypt>`
          `big ass key`
          `</tls-crypt>`
          
    * on client side, add `nobind` to conf to ensure it uses a diffrent port
          each time it makes a connection so all traffic isn't to and from `443`
    * force to ensure that clients can't act like servers and vice-versa
        add to .conf files. Will only accept connections from the below line
        `remote-cert-tls client` to SERVER conf
        `remote-cert-tls server` to CLIENT conf
        
    * standardize common name to only accept certs with that name
        `verify-x509-name jacket-client name-prefix` on server
            name-prefix here means jacket-client*
        `verify-x509-name jacket-server name` on client
    * openvpn runs sudo by default to interact with interfaces less lower that
        `user nobody`
        `group nobody`
        `persist-key`
        `persist-tun`
        `chroot jacket-jail`
        * you need to make a tmp dir for openvpn to use
        `sudo mkdir -p /etc/openvpn/jacket-jail/tmp`
        `sudo chmod 1777 /etc/openvpn/jacket-jail/tmp`
        `sudo vim /etc/openvpn/jacket-server.confi`
    
    * protocol downgrade to control the data channel encryption
        `tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384`
        `tls-version-min 1.3 or-highest`
        
    * CRL certificate revocation list so we can remove compromised certs
        on our `certificate authority` use the github for `easyrsa`
        `./easyrsa gen-crl`
        `mv pki/crl.pem pki/crl-good.pem`
        * place `crl-good.pem` on the server each time it is updated in:
            `/etc/openvpn` and `/etc/openvpn/jacket-jail`
            * server will look at the crl each time a client connects by adding to conf
            `crl-verify crl-good.pem`
            
        * to revoke a cert, be on the CA and use easyrsa
        `./easyrsa revoke jacket-client2`
            *then remake crl and transfer to the server
            `./easyrsa gen-crl`
        # everytime you make a new cert or revoke one you must:
            `./easyrsa gen-crl` then send that new crl to server
            
# Deploying OpenVPN
* so we have build all our openvpn server and clients and tested them on 2
  practice boxes. We need to take thouse good configs and put them on real
  servers and clients
  # useful sites
    `dnsleasktest.com` to check for dns leakage need web browser
    `ipinfo.io` curl this to get country into on your public ip
    `icanhazip.com` curl this to just get your public ip
    
  * create new `ta.key` for network on `CA` in `easy-rsa/easyrsa3/pki`
    `openvpn --genkey --secret ta.key`
  * create `directives` then add them to `certs` and `ta.key`
    `cat <name>-client.directives <name>client.creds ta.key > <name>-client.conf`
    * don't forget to add `<tls-crypt>` and `</tls-crypt>` around the `ta.key`
    [server_directives](server_directives) for p2p
    [client_directives](client_directives) for p2p
  * move client conf from test client to real client
  * on both configs change:
      * interface
      * port
      * source_IP and remote_IP
      * remote (client side)
      * name
  * install openvpn on server and all clients
  * make the `<name>-jail` dir and change permissions on BOTH!!!
    `sudo mkdir -p /etc/openvpn/<name>-jail/tmp && sudo chmod 1777 /etc/openvpn/<name>-jail/tmp`
  * if `systemctl` failes run as `sudo openvpn --config <name>-server.conf`
  
      #DNS leak plugging on server
      * on server edit server conf and add:
          `push "redirect-gateway def1"`
          `push "dhcp-option DNS 1.1.1.1"`
          `push "block-outside-dns"`
        * then initialize it with `sudo sysctl -p`
      * need to edit the NAT table so our client ip is hidden behind the
        servers public ip (the ip here is the VPN ip network address). this
        takes all traffic from the VPN network and pushing it out eth0 will
        look like they come from the public ip of eth0
        `iptables -t nat -A POSTROUTING -s 10.106.0.0/24 -o eth0 -j MASQUERADE`
      # to route thru server
      * enable ipv4 forwarding by uncommenting `net.ipv4.ip_forward=1` in
        `/etc/sysctl.conf`
      
      #for pass thru on a server with ipv4 forwarding
      bob > alice (server) > eve
      * add push route to server configs so server updates bob and eve iproutes
        everytime they connect
        `push "route < network ip> <full cidr>"`
      * on server enable ipv4 forwording by editing `/etc/sysctl.conf` and
        uncomment line `#net.ipv4.ip_forward=1` and then run `sysctl -p`
        
      
      
  
  * restart opnvpn on server and cleints
  * check ping client to server
  * on client `curl ipinfo.io` to besure u terminate in servers country
  * open client in browser and check dnsleaktest.com to besure DNS don't leak
      
      
      
    `tcpdump -ni <interface> icmp`
      
# IP tables are the firewall
* see firewall rules
    `iptables -nvL` each is called a Rule Chain on the Filtered Table
    * INPUT - all outside traffic from outside destin for in
    * OUTPUT - all traffic originated from in going to outside
    * FORWARD - all traffic from outside going thru box destin for outside

    `iptables -t nat -nvL --line-numbers` 4 chains on the NAT table
    * PREROUTING - before anything rules are ran, do this first
        `iptables -t nat -A PREROUTING -i eth0 -p udp -m udp --dport 11195 -j DNAT --to-destination 10.x.0.2`
            * this will nat the packet by changing its destination to 10.x.0.2
    * INPUT
    * OUTPUT
    * POSTROUTING - on the way out, do this
        `iptables -t nat -A POSTROUTING -o con0 -p udp -m udp --dport 11195 -j SNAT --to-source 10.x.2.2`
            * this will nat the packet by changing its source to 10.x.2.2 (this box)
            * If network is A&B and B&C for A&C to talk you need to enable ipv4
              fowarding on box B (A&B network on interface eth0, B&C network on
              interface eth1) and add 2x POSTROUTING rules on box B
            `iptables -t nat -A POSTROUTING -o <eth1> -j SNAT --to-source <this box_ip>`
            `iptables -t nat -A POSTROUTING -o <eth0> -j SNAT --to-source <this box_ip>`
        * MASQUERADE - NATs the packet before it goes to the internet by changing
          it to the public ip of the box this rule is on.
          * every packet leaving `eth0` will have its source changed to this box's
            public IP to ensure the packets come back to this box.
              `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE`
    * CentOS - disable firewalld and then iptables will be the only firewall.
        `sudo systemclt stop firewalld`
        `sudo systemclt disable firewalld`
 
* iptables are checked in order from top to bottom and then check their policy (INPUT, FORWARD, OUTPUT)
* adding NEW rules
    `iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCPET`
* delete a rule, insert, replace
    `iptables -nvL --line-numbers` to get line numbers then:
    `iptables -D INPUT 8` removes rule 8 from INPUT policy
    `-I` insert a rule at a number `-R <chain> <line number> <rule>`
    `-R` replace a rule with another one `-R <chain> <line number> <rule>`
    `sudo iptables -R INPUT 5 -p tcp -m tcp --dport 20022 -m conntrack --ctstate NEW -j ACCEPT`
        `-p` protocol
        `-m` name
        `--dport` specific port
        `--cstate` states of packets NEW, RELATED, ESTABLISHED, INVALID
        `-j` jump to ACCEPT or DENY
* change a policy
    `iptables -P INPUT DROP` changes input policy to drop all that do not follow rules below
    
* you need to have this package installed for rules.v4 to work!
    `apt install iptables-persistent`
* to save iptables changed in RAM to the file that is loaded on boot
    `iptables-save | sudo tee /etc/iptables/rules.v4 `

    * if you are loading a moved rules file test with iptables-apply
    * lets you set the rules for a limited amount of time so you can ssh from
      another terminal and be sure you didn't fuck yourself. 
        `iptables-apply -t 30 /tmp/rules.v4`
* rules to add
    [generic_rules](generic_rules)
    
#ip routes
https://www.golinuxcloud.com/ip-route-command-in-linux/
* follows routes from most specific to least specific, then default
    `ip route` to see routes
* to add a static route
    `ip route add <ip address/cidr> via <network ip> dev <interface>`
* to del a route
    `ip route delete <ip/cider> via <netowrk ip> dev <interface>`
* check pings
    `tcpdump -ni <interface> port <port> icmp`
    #trouble shooting
    * check `iproutes`
    * check `iptables`
    * when an interface is restarted all routes for it are dropped!

* iproutes are saved in ram so for persistance you need to edit `/etc/netplan`
    * netplan.io can help

 


        
#burning Execution of a VPS
* get a root shell `sudo -i`
* stop the openvpn service
* we need to remove all our openvpn keys and configs
`shred -vvuzn 2 /etc/openvpn/jacket*`
* remove auth logs of all ips that authenticated and sudo cmds
`shred -vvuzn 2 /var/log/auth.log`
* find name of drive OS is on and overwrite it with null bytes
`lsblk | grep disk`
`nohup sudo dd if=/dev/zero of=/dev/<drive name> & disown`
    * drive name should be `vda`








