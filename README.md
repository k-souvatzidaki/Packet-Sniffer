# Packet Sniffer
## About 
A simple *data-link layer* Ethernet (802.3) packet sniffer in Python. Using the **PyPCAP** libpcap module ,and *npcap* for Windows 10 compatibility. Unpacking frame headers, starting from data-link, and printing information.

## Run
...

## PyPCAP installation guideline for Windows 10
1. Install Npcap
2. Download the Npcap SDK and place it in the hd root directory as "C:\wpdpack" (the name "wpdpack" is mandatory for PyPCAP to recognise Npcap)
3. Download the PyPCAP source and place it in the root directory as well, as "C:\pypcap-1.1.4"
4. Install the Microsoft Visual C++ Compiler for Python 2.7
5. Start a command prompt for the compiler and install PyPCAP with the following instructions: 
~~~~
set INCLUDE=%INCLUDE%;c:\WpdPack\Include
set LIB=%LIB%;c:\WpdPack\Lib
pushd C:\pypcap-1.1.4
python setup.py install
~~~~
