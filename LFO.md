# LFO - Linux for Operators

# Linux boot steps
----------------------------------------------------------------------
* 1.) BIOS / UEFI
    * Basic Input Output System - loads low level drivers, checks bootloader,
        load system date/time from CMOS
    * legacy system replaced by UEFI in 2007
    * Unified Extensible Firmware Interface - will effect booting form USB
    * can be set to "legacy" or " (CSM) Compatibility Support Mode"

* 2.) MRB
    * Master Boot Record - first sectors of hd contains inital code to assist
      bootloader loading OS, restricted to 2TB or less, 4 primary partions
    * GPT - GUIP partion Tables - replaced MBR (not compatable with bios in
      windows) supports drives larger than 2TB can have 128 partions. has
      backwards compatibility and reserves 1st sector for MBR and takes 2nd for
      self
      
* 3.) GRUB
    * grand unified bootloader - bootloader's main function locates kernal and
      loads `initramfs` to RAM to assist with OS loading. Gives you boot
      options instead of loading default runlevel 3 or 5.
      
 * 4.) Kernal
    * begings to config memory, storage, and other I/O subsystes. Then looks
      for initramfs image, mounts root file system, an dloads all drivers and
      unmounts initramfs image once root is stable and drivers are loaded.
      
* 5.) SystemV (System5 or init)/ SystemD (System Daemon)
    * SystemV was old manager form Unix. (Upstart was between V and D)
    * SystemD assigned PID of 1 and allows for user level login. service
      manager for linux and is now used.
      
* 6.) RunLevel 
    * known as targets in systemd is last phase of boot process. Most of the
      time RunLevel 3 or 5 is used.
      Runlevel 0 Shuts down the system
      Runlevel 1 Single user mode. Used for maint and admin tasks (can be used
      to bypass a user password)
      Runlevel 2 Multi-user mode without any networking services
      Runlevel 3 Multi-user mode with networking without a GUI
      Runlevel 4 Customizable runlevel
      Runlevel 5 Multi-user mode with networking and a GUI
      Runlevel 6 Reboots the system
      
#ubuntu shit
----------------------------------------------------------------------
* to has a file with SHA256
    `certutil -hashfile <file> SHA256`

* check system info
   `cat /etc/os-release`
   `lsb_release -a`
   `hostnamectl`
        `sudo hostnamectl set-hostname taco-server` will change hostname
   `dpkg -l | grep Desktop` if you get over 3 results its a Desktop not a server
   
* display a file's stats
    `stat <file>`
    `touch <file1> -r <file2>` replaces file1's timestamp with file2's as seen
        by `stat`

* change default editor
    `sudo update-alternatives --config --editor`
    
* Environment Variables
    * `echo $<var>` to call the var
    `PATH` loooks for executable files when running a command
    `HIST` bash history line count. managed in `~/.bashrc`
    `SHELL` to see shell type
    
* change your shell
    `chsh -s /bin/<shell>`
    
* customize bash prompt: https://tldp.org/HOWTO/Bash-Prompt-HOWTO/bash-prompt-escape-sequences.html

* command substitution `$(<a cmd>)`
    * used inside a another command
    * will run `date` and then take the first word in the output and add it to
      the echoed text
        `echo "Today is $(date | cut -d ' ' -f 1)! Have a good day"` 
        
* rerun setup script from a package
    `dpkg-reconfigure <package name>`
    
* apt
    `upgrade` upgrades all packages except for kernel packages
    `dist-upgrade` upgrades kernal to latest version 
    
* single line of what a command is
    `whatis <command>`
* searchs man pages for commands related to search
    `apropos <term>`
    
#linux file system
----------------------------------------------------------------------
`/bin` is a place for most commonly used `terminal commands`, like ls, mount, rm, etc.
`/boot` contains files needed to `start up` the system, including the Linux
    kernel, a RAM disk image and bootloader configuration files.
`/dev` contains all `device files`, which are not regular files but instead
    refer to various hardware devices on the system, including hard drives.
`/etc` contains `system-global configuration files`, which affect the 
    system's behavior for all users.
`/home` home sweet home, this is the place for users' home directories.
`/lib` contains very important `dynamic libraries` and `kernel modules`
`/media` is intended as a `mount point for external devices`, such as 
    hard drives or removable media (floppies, CDs, DVDs).
`/mnt` is also a place for mount points, but dedicated specifically to
    `temporarily mounted` devices, such as `network filesystems`
`/opt` can be used to store additional software for your system, 
    which is not handled by the package manager.
`/proc` is a `virtual filesystem` that provides a mechanism for kernel to 
    send information to processes.
`/root` is the superuser's home directory, not in /home/ to allow for 
    booting the system even if /home/ is not available.
`/run` is a tmpfs (temporary file system) available early in the boot process 
    where ephemeral run-time data is stored. Files under this directory 
    are removed or truncated at the beginning of the boot process.
`/sbin` contains important `administrative commands` that should generally 
    only be employed by the superuser.
`/srv` can contain `data directories` of services such as HTTP (/srv/www/) or FTP.
`/sys` is a virtual filesystem that can be accessed to set or obtain 
    information about the kernel's view of the system.
`/tmp` is a place for temporary files used by applications.
`/usr` contains the `majority of user utilities and applications`, and 
    partly replicates the root directory structure, containing for instance, 
    among others, `/usr/bin/` and `/usr/lib`.
`/var` is dedicated to `variable data`, such as `logs`, databases, websites, 
    and temporary spool (e-mail etc.) files that persist from one boot to the 
    next. A notable directory it contains is /var/log where system log files are kept. 
    * important files and folders
    `/var/log/syslog`     The system log. This file contains many useful things, 
        and some applications write their logs to it as well.
    `/var/log/auth.log`     Contains a record of successful and unsuccessful
        attempts to connect to the system or gain superuser privs
    `/var/log/wtmp` and /var/log/btmp     Contains a record of successful 
        logins (wtmp) and bad login attempts (btmp).
    `/var/tmp`     Temporary files that persist between reboots.
    `/var/www/html`     The usual directory where the Apache web server stores files to be served.

`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` are where binary files for executing commands on the operating system are kept.
	`/bin` and `/sbin` are necessary to boot
    
#Special Files
----------------------------------------------------------------------
* running `ls -l` will so you the permissions of a file. the first bit
    tells you what find of file it is: `d`rwxr-xr-x
    * letter    file type
        -       regular file
        d       directory
        l       symbolic link
        c       character device
        b       block device
        p       named pipe
        s       socket
        
* helpful files
`/dev/null` Discards anything sent to it.
`/dev/random` Outputs random numbers to any program that asks for them. 
	Often use to generate cryptographic keys.
`/dev/sda` First physical disk on the system. Only exists if a disk is connected.
`/dev/vda` First virtual disk on the system. Same deal.
`/dev/zero` Outputs an endless stream of zeroes to any program that asks. 
	Often used to overwrite disks. 

* most linux distros have 6 virtual consoles to access them with:
    `Alt+F1-6` or `Ctrl+Alt+F1-6`
    
# Users, Groups, and World or Other Permissions
----------------------------------------------------------------------
* UIDs > 500, come with the system and are called system groups

* World or Other permissions - this is public permissions or permissions
     for logistics who isn't the owner or member of the group of the resouce
     
* Users - a single user on the system with certain permissions
    * view ALL users with `vipw`
    * view hashed passwords of users with `vipw -s` only users have hashes
    `adduser <name>`    for an interactive creation
        `deluser` remove user interactive
    `useradd <name> <flags>` for non interactive, use in scripting
        `userdel` remove user non-interactive
        
    `chown <new user>:<new group> <file>` change ownership of a resource
        * if a side of `:` is left blank it will not change
        `-R` recursively

* Groups - a group of users that have permissions
    * view ALL groups with `vigr`
    `addgroup` interactive creates a group
        `delgroup` interactive remove group
    #admin access
    `addgroup <group name> <user>` will add a user to a group
        * to give user admin access, add them to `sudo` group or `wheel` if
        there is no sudo group
            `sudo addgroup <user> sudo`
    `groupadd` non-interactive
        `groupdel` non-interactive remove group
    * to remove a user from a group: `deluser <user> <group>`
        
    `chgrp` change group ownership of resource
    
* Permissions `ls -l` 
  type, user, group, world (or other)
  `- rwx rwx rwx`
  * to change permissions by letter or number
    `chmod <catagory> <+ or -> <permission> <file>`
        * add execute privs to user and group for file.sh
            `chmod ug+x file.sh`
    `chmod <number> <file>`
        read=4, write=2, execute=1
        * set user to `rwx`, group to `-xr`, and other to `---`
        `chmod 750 file.sh`

* Special Permissions for directories
    * changes `x` to `s` for user and group, 
    * this bit is always at the front, SUID = 4, GUID = 2, sticky bit = 1
      
    * SUID (`s`) - set userid - makes program executable with permissions of owner
          NOT current user
          `chmod u+s` or `chmod 4xxx`
    * SGID (`s`) - set groupid - makes program executable with permissions of group
          NOT current user. When set on a dir, all new files with have the
          dir's group not the users
          `chmod g+s` or `chmod 2xxx`
    * sticky (`t`) - restrict modifications and deletions in this dir. Used to
          let many/all users write and access but only the owner or group of a file
          can remove it
          `chmod +t` or `chmod 1xxx`
          
#live disk or live usb with persistence storage
----------------------------------------------------------------------

#harden linux
----------------------------------------------------------------------
* during installation add a password to encrypt with LUKS during install
    will require a password to boot
* also can encrypt the swap (used when RAM is full)
    * edit `/etc/crypttab` and add line:
        `crypt_swap /swap.img /dev/urandom swap`
    * edit `/etc/fstab` comment out `/swap.img` line and add:
        `/dev/mapper/crypt_swap none swap sw 0 0`
    * reboot


#bash scripting
----------------------------------------------------------------------
* stdout = 1, stderr = 2, stdin = 0
`>` redirect stdout
    if the right side needs sudo you need to use `| sudo tee` instead
`>>` append stdout
`<` redirect stdin
    `sort < list.txt` redirect list.txt as stdin to sort cmd
    `sort < list.txt > list.txt` redirect list.txt as stdin to sort then
        redirect stdout back to list.txt so the list is now sorted
    `ls -l /etc 2>/dev/null` redirect stderr to dev/null
    `ls -l /etc 2>&1` will redirect stdout and stderr to same spot
        `&>` means the same thing as `2>&1`
        
`:w !sudo tee <filename>` will save a file you opened with vim not in sudo

`&` at the end of a cmd will background it
    call it forward wtih `fg`
    * ping an ip, don't see the output, and background
        `ping <ip> > /dev/null &`
    * now see the pings with tcpdump
        `tcpdump -ni <interface> icmp`
        * to stop ping type `fg` then `Ctrl+c`

# Processes and job signals
`ps aux`
    see process, with userlist, that have PID
`Ctrl+x`
    background a process if you forget to put `&` at the cmd end but will
    suspend it
`bg`
    will tell backgrounded job to run in background.
`fg`
    bring up backgrounded process
`jobs`
    will list all background jobs by number
    `bg 3` will run job 3
    `kill %3` will kill job 3. `kill -9 %3` to nuke job 3
    * if you disconnect ALL jobs will die because they are sent the `HUP`
      (handup signal). To prevent this run:
    `nohup <cmd> & disown` will not accept handup and remove it form users job
        table.
        
# Partitions and File Systems
`lsusb`
    list all usb devices and hds
`lsblk`
    list block devices
`fdisk -l`
    list the partition tables
`sudo cfdisk /dev/<device>`
    partition a device
`sudo mkfs.ex4 /dev/<device>`
    will creat an ext4 filesystem on the device
    * NTFS(Win) HFS(Mac) FAT(oldschool) ext(Linux) FAT32(for all)

* mounting and unmounting 
   * if you get a `busy` error you might be in the dir so move or run
        `lsof | grep /mnt` to see what is accessing the mounted partition
`sudo mount /dev/<device> /mnt`
    will mount our usb device <device> to the `/mnt` dir so we can access it
`mount | grep <device>`
    to see if its mounted
`umount /mnt/`
    umount device mounted to `/mnt`
    `-f -l` for lazy dismount and force
`eject /dev/<devive>`
    will eject it from system digitally
    
* mounting container on boot
* on boot any custom files sytems will not be mounted, for them to be you need
  to edit `/etc/fstab` as it tells linux what to mount on boot
  `/home/studentx/unencrypted_container /mnt ext4 defaults 0 2`
    adding this to the end of the `fstab` will mount it on boot

* encryption
---------------------------------------------------------------------- 
`cryptsetup luksFormat /dev/<device>`
    encrypts a device with LUKS
    `blkid` to check it, should be `crypto_LUKS` (if its usb try to mount it
    and it will error saying it doesn't know what crypto_LUKS is)
`cryptsetup luksOpen /dev/<device> <partition name>`
    check this with `ls -alh /dev/mapper/` it has to be opend with mapper
        before we can mount it
`mount /dev/mapper/<partition name> /mnt`
    to mount encrypted partionton
    `mkfs.ext4 /dev/mapper/<partition name>`
        to create a partion on the new encrypted drive if you need one
`umount /dev/mapper/<partition name>`
    unmount partion
`cryptsetup luksClose /dev/mapper/<partition name>`
    to re-encrypt (close) the device
    
* handmade encrypted container (not hidden but encrypted)
* can be moved to other linux systems and opened
`sudo fallocate -l 200M /tmp/container`
    create a container that is 200 megabytes in size
`sudo cryptsetup luksFormat /tmp/container`
    encrypted it
`sudo cryptsetup luksOpen /tmp/container encrypted_container`
    decrypted (open) it
`sudo mkfs.ext4 /dev/mapper/encrypted_container`
    create a ext4 filesystem in container
`sudo mount /dev/mapper/encrypted_container /mnt`
    mount it
* do save files to it
`sudo umount /dev/mapper/encrypted_container`
    umount it
`sudo cryptsetup luksClose /dev/mapper/encrypted_container`
    encrypt (close) the container
    
* mounting encrypted container on boot
    * edit `/etc/cryttab` to decrypted the container and call the new continer
          encrypted container
          `encrypted_container /home/studentx/container none luks`
    * then edit `/etc/fstab`
       `/dev/mapper/encrypted_container /mnt ext4 defaults 0 2`
       
* mounting encrypted partion at boot like on a usb
    * linux might change the `/dev/` location for a usb so we need to know the
        UUID of the partion on the usb.
        `blkid | grep <device>`
    * make a dir that we will mount to each time
        `mkdir /opt/usb`
        * easy way to copy the UUID to crypttab
        `echo $(sudo blkid | grep <device> | cut -d' ' -f2 | tr -d "\"") | sudo tee -a /etc/crypttab`
    * edit `/etc/crypttab` with UUID and location
        `encrypted_usb UUID=<uudi> none luks`
    * edit `/etc/fstab`
        `/dev/mapper/encrypted_usb /opt/usb ext4 defaults 0 2`
        
* if you can't resolve hostnames and only ping ips or can't get apt update to
      work edit `/etc/resolv.conf` and change `nameserver` to `9.9.9.9`
* for persistance edit `/etc/netplan/_config.yaml` and edit `search: [9.9.9.9]`

    

    

    
    



        




          
        
    
    
    

                
