#Network layer protocol based on MAC Ethertype
def get_network_prot(ethertype):
    if(ethertype == int('0800',16)):
        return "IPv4"
    if(ethertype == int('0806',16)):
        return "ARP"
    return "x"

#Transport layer protocol based on IP protocol field
def get_transport_prot(protocol):
    if(protocol == '06'):
        return "TCP"
    if(protocol == '11'):
        return "UDP"
    if(protocol == '02'):
        return "IGMP"
    return "x"

#IGMP message types
def IGMP_type(hex):
    if(hex == "11"):
        return "Membership Query"
    elif(hex == "12"):
        return "IGMPv1 Membership Report"
    elif(hex == "13"):
        return "DVMRP"
    elif(hex == "14"):
        return "PIM version 1"
    elif(hex == "16"):
        return "IGMPv2 Membership Report"
    elif(hex == "17"):
        return "IGMPv2 Leave Group"
    elif(hex == "1e"):
        return "Multicast Traceroute Response"
    elif(hex == "1f"):
        return "Multicast Traceroute"
    elif(hex == "22"):
        return "IGMPv3 Membership Report"
    return "x"

#TCP/UDP ports application layer protocols (well-known)
def port_protocol(port):
    #most popular well-known ports
    if(port == 20):
        return "File Transfer Protocol (FTP) data"
    elif(port == 21):
        return "File Transfer Protocol (FTP) control"
    elif(port == 22):
        return "Secure Shell Protocol (SSH)"
    elif(port == 23):
        return "Telnet Protocol"
    elif(port == 25):
        return "Simple Mail Transfer Protocol (SMTP)"
    elif(port == 53):
        return "Domain Name System(DNS) Protocol"
    elif(port == 67):
        return "Bootstrap Protocol (BOOTP) Server / Dynamic Host Configuration Protocol (DHCP)"
    elif(port == 68):
        return "Bootstrap Protocol (BOOTP) Client / Dynamic Host Configuration Protocol (DHCP)"
    elif(port == 69):
        return "Trivial File Transfer Protocol (TFTP)"
    elif(port == 80):
        return "Hypertext Transfer Protocol (HTTP)"
    elif(port == 110):
        return "Post Office Protocol (POP3)"
    elif(port == 115):
        return "Simple File Transfer Protocol["
    elif(port == 118 or port == 156):
        return "Structured Query Language (SQL) Services"
    elif(port == 119):
        return "Network News Transfer Protocol (NNTP)"
    elif(port == 123):
        return "Network Time Protocol (NTP)"
    elif(port == 143):
        return "Internet Message Access Protocol (IMAP) Management of Digital Mail"
    elif(port == 158):
        return "Distributed Mail System Protocol (DMSP)"
    elif(port == 121):
        return "Simple Network Management Protocol (SNMP)"
    elif(port == 194):
        return "Internet Relay Chat (IRC)"
    elif(port == 209):
        return "Quick Mail Transfer Protocol["
    elif(port == 220):
        return "Internet Message Access Protocol (IMAPv3)"
    elif(port == 319):
        return "Precision Time Protocol (PTP) Event"
    elif(port == 320):
        return "Precision Time Protocol (PTP) General"
    elif(port == 389):
        return "Lightweight Directory Access Protocol (LDAP)"
    elif(port == 401):
        return "Uninterruptible power supply (UPS)"
    elif(port == 427):
        return "Service Location Protocol (SLP)"
    elif(port == 443):
        return "Hypertext Transfer Protocol Secure (HTTPS)"
    return "None"

def ARP_HTYPE(hardware_type):
    if(hardware_type == 1):
        return "Ethernet"
    elif(hardware_type == 2):
        return "Experimental Ethernet"
    elif(hardware_type == 1):
        return "IEEE 802"
    return "x"

def ARP_OPERATION(operation):
    if(operation == 1):
        return "Request"
    elif(operation == 2):
        return "Reply"
    return "x"