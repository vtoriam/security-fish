*I have redacted sensitive information by either using [REDACTED], X or blacked out*

Finding router IP address:
```
PS C:\Users\[REDACTED]> ipconfig
Windows IP Configuration

Ethernet adapter Ethernet:
   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : [REDACTED]
   IPv4 Address. . . . . . . . . . . : 192.168.X.X
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :

Ethernet adapter Ethernet 2:
   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : [REDACTED]
   IPv4 Address. . . . . . . . . . . : 192.168.X.16
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.X.1

Wireless LAN adapter Local Area Connection* 1:
   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter Local Area Connection* 2:
   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter Wi-Fi:
   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Ethernet adapter Bluetooth Network Connection:
   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Ethernet adapter vEthernet (WSL (Hyper-V firewall)):
   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : [REDACTED]
   IPv4 Address. . . . . . . . . . . : 172.29.X.1
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . :
```

Ping scan
```
PS C:\Users\[REDACTED]> nmap -sn 192.168.X.0/24
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-01 15:39 +0800

Nmap scan report for 192.168.X.1
Host is up (0.0010s latency).
MAC Address: XX:XX:XX:XX:XX:XX (Netgear)

Nmap scan report for 192.168.X.3
Host is up (0.049s latency).
MAC Address: XX:XX:XX:XX:XX:XX (Motorola)

Nmap scan report for 192.168.X.4
Host is up (0.048s latency).
MAC Address: XX:XX:XX:XX:XX:XX (Arlo Technology)

Nmap scan report for 192.168.X.6
Host is up (0.065s latency).
MAC Address: XX:XX:XX:XX:XX:XX (Beijing Roborock Technology)

Nmap scan report for 192.168.X.9
Host is up (0.058s latency).
MAC Address: XX:XX:XX:XX:XX:XX (Unknown)

Nmap scan report for 192.168.X.18
Host is up (0.042s latency).
MAC Address: XX:XX:XX:XX:XX:XX (Unknown)

Nmap scan report for 192.168.X.19
Host is up (0.0010s latency).
MAC Address: XX:XX:XX:XX:XX:XX (Brother Industries)

Nmap scan report for 192.168.X.23
Host is up (0.0010s latency).
MAC Address: XX:XX:XX:XX:XX:XX (Intel Corporate)

Nmap scan report for 192.168.X.29
Host is up (0.0010s latency).
MAC Address: XX:XX:XX:XX:XX:XX (Intel Corporate)

Nmap scan report for 192.168.X.30
Host is up (0.0010s latency).
MAC Address: XX:XX:XX:XX:XX:XX (Dell)

Nmap scan report for 192.168.X.15
Host is up.

Nmap scan report for 192.168.X.16
Host is up.

Nmap done: 256 IP addresses (12 hosts up) scanned in 14.49 seconds
```
* 4 unknown devices (9, 15, 16, 18)
* Several IoT devices (camera, vacuum, printer) which are security risks if not on a separate guest network
* Two intel devices with the same MAC address (15.23 and 15.29) which is unusual

```
PS C:\Users\[REDACTED]> nmap -sV 192.168.X.1
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-01 15:44 +0800

Nmap scan report for 192.168.X.1
Host is up (0.0012s latency).
Not shown: 994 closed tcp ports (reset)

PORT      STATE     SERVICE  VERSION
21/tcp    filtered  ftp
22/tcp    filtered  ssh
23/tcp    filtered  telnet
53/tcp    open      domain   dnsmasq UNKNOWN
80/tcp    open      http     micro_httpd
5431/tcp  open      upnp     Belkin/Linksys wireless router UPnP (UPnP 1.0; BRCM400 1.0)

MAC Address: XX:XX:XX:XX:XX:XX (Netgear)
Service Info: OS: Linux 3.4; Device: router; CPE: cpe:/o:linux:linux_kernel:3.4

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
Nmap done: 1 ip address (1 host up) scanned in 14.82 seconds
```
* Telnet (port 23) - High Risk
	* Outdated, unencrypted protocol
	* Even though it is filtered, its presence is a concern
	* Disable telnet in router admin panel
* UPnP (port 5431) - High Risk
	* UPnP allows devices to automatically open ports -> known security vulnerability
	* Can be exploited by malware on network
	* Disable UPnP in router settings
* HTTP (port 80) - Medium Risk
	* Router admin panel is accessible over unencrypted HTTP
	* Use HTTPS access if router supports it
* FTP and SSH (ports 21/22) - Filtered
	* Blocked but still visible
	* Disable if not in use

Turn UPnP Off:

<img width="642" height="479" alt="image" src="https://github.com/user-attachments/assets/82c3e3d2-b28b-46cf-8ba5-786e87cdd540" />


Turn off Telnet/Remote Management:

<img width="803" height="181" alt="image" src="https://github.com/user-attachments/assets/54448d1d-6970-41ac-83d3-cc459977144a" />


Create Guest Network:

<img width="1525" height="642" alt="image" src="https://github.com/user-attachments/assets/bc099098-bf70-4e56-ba97-3533454ca6b8" />


```
PS C:\Users\[REDACTED]> netsh wlan show interfaces

There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6E AX211 160MHz
    GUID                   : [REDACTED]
    Physical address       : XX:XX:XX:XX:XX:XX
    Interface type         : Primary
    State                  : connected
    SSID                   : [REDACTED]
    AP BSSID               : XX:XX:XX:XX:XX:XX
    Band                   : 5 GHz
    Channel                : 157
    Connected Akm-cipher   : [ akm = 00-0f-ac:02, cipher = 00-0f-ac:04 ]
    Network type           : Infrastructure
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Receive rate (Mbps)    : 390
    Transmit rate (Mbps)   : 650
    Signal                 : 84%
    Rssi                   : -55
    Profile                : [REDACTED]
    QoS MSCS Configured    : 0
    QoS Map Configured     : 0
    QoS Map Allowed by Policy : 0
```
* WPA2-Personal - Secure, but not gold standard
	* Router does not support it
* CCMP (AES) Cipher
	* Strongest cipher available for WPA1
* 5 GHz Band
	* Shorter range than 2.4 GHz, meaning it is harder for neighbours to reach network

DNS Testing:

<img width="2457" height="1052" alt="image" src="https://github.com/user-attachments/assets/3dedb5b1-40ec-4fcd-bd4c-ea77f91bfbe5" />

* No foreign or unexpected DNS servers
* No DNS leak - all servers are in Australia and belong to my ISP, no unexpected third-party servers intercepting traffic

Disable WPS:

<img width="711" height="1170" alt="image" src="https://github.com/user-attachments/assets/9596119c-0fda-4393-bab8-ed1894c43e5a" />

