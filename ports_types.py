#Network layer protocol based on MAC Ethertype
def get_network_prot(ethertype):
    if(ethertype == int('0800',16)):
        return "IPv4"
    if(ethertype == int('0806',16)):
        return "ARP"

#Transport layer protocol based on IP protocol field
def get_transport_prot(protocol):
    if(protocol == '06'):
        return "TCP"
    if(protocol == '11'):
        return "UDP"
    if(protocol == '02'):
        return "IGMP"

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

#TCP ports application layer protocols (well known)
def TCP_port(port):
    #TODO add well known ports
    return 0