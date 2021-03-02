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
    return 0