import pcap, unpacking

def main():
    cap = pcap.pcap(None)
    print('Listening on %s: %s' % (cap.name, cap.filter))
    print("\n====================================================================================== \n")
    i = 1
    for d, packet in cap:
        print("Packet #"+str(i) +" Length = "+str(len(packet)))
        unpack(packet)
        i = i+1
        print("\n====================================================================================== \n")
        

def unpack(packet):
    #MAC
    print("Data-Link Layer: MAC")
    #unpacking MAC header
    dst, src, ethertype, mac_data = unpacking.unpack_MAC(packet)
    print "     Destination MAC: " + dst
    print "     Source MAC: " + src

    # Network Layer
    net_prot = get_network_prot(ethertype)
    if(net_prot == "IPv4"): 
        print("Network Layer: IPv4")
        #unpacking IP header
        version, length_bytes, total_length, ttl, protocol, src, dst, payload = unpacking.unpack_IPv4(mac_data)
        print "     Version: "+str(version)
        print "     Header length: "+str(length_bytes)+" bytes"
        print "     Total length: "+str(total_length)+ " bytes"
        print "     Time to Live: "+str(ttl)
        print "     Destination IP: " + str(dst)
        print "     Source IP: " + str(src)

        # Transport Layer
        trans_prot = get_transport_prot(protocol)
        if(trans_prot == "TCP"):
            print("Transport Layer: TCP")
            src, dst = unpacking.unpack_TCP(payload)
            print "     Source port: " + str(src)
            print "     Destination port: " + str(dst)
        if(trans_prot == "UDP"):
            print("Transport Layer: UDP")
            src,dst,length = unpacking.unpack_UDP(payload)
            print "     Source port: " + str(src)
            print "     Destination port: " + str(dst)
            print "     Length: " + str(length)
        if(trans_prot == "IGMP"):
            print("Transport Layer: IGMP")
            version_type, group_addr = unpacking.unpack_IGMP(payload)
            print "     Message Type: " + str(version_type)
            print "     Group Address: " + str(group_addr)


def get_network_prot(ethertype):
    if(ethertype == int('0800',16)):
        return "IPv4"
    if(ethertype == int('0806',16)):
        return "ARP"

def get_transport_prot(protocol):
    if(protocol == '06'):
        return "TCP"
    if(protocol == '11'):
        return "UDP"
    if(protocol == '02'):
        return "IGMP"

main()