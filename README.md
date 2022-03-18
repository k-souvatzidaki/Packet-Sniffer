# Packet Sniffer
## About 
A simple *data-link layer* Ethernet (802.3) **raw** packet sniffer in Python. Using the **PyPCAP** libpcap module ,and *npcap* for Windows 10 compatibility. Unpacking frame headers, starting from data-link, and printing information.

# Supported Protocols
## Data-Link Layer
- MAC
## Network Layer
- IPv4
- ARP
## Transport Layer
- TCP
- UDP
- IGMP

## Run
~~~~
python sniffer.py
~~~~

## PyPCAP installation guideline for Windows 10
Reading raw Data Link Layer packets in Windows 10 is a bit tricky but it works by replacing WpdPack with Npcap while installing PyPCAP
1. Install [Npcap](https://nmap.org/npcap/)
2. Download the [Npcap SDK](https://nmap.org/npcap/) and place it in the hd root directory as "C:\wpdpack" (the name "wpdpack" is mandatory for PyPCAP to recognise Npcap)
3. Download the [PyPCAP source](https://pypi.org/project/pypcap/#files) and place it in the root directory as well, as "C:\pypcap-1.x.x"
4. Install the [Microsoft Visual C++ Compiler for Python 2.7](https://www.microsoft.com/en-us/download/details.aspx?id=44266)
5. Start a command prompt for the compiler and install PyPCAP with the following instructions: 
~~~~
set INCLUDE=%INCLUDE%;c:\WpdPack\Include
set LIB=%LIB%;c:\WpdPack\Lib
pushd C:\pypcap-1.x.x //the installed version
python setup.py install
~~~~
