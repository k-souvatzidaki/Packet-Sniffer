import pcap, unpacking

def main():
    cap = pcap.pcap(None)
    print('listening on %s: %s' % (cap.name, cap.filter))
    
    for d, packet in cap:
        #unpacking MAC (Ethernet) header
        dst, src, mac_data = unpacking.unpack_MAC(packet)
        print "Destination MAC: " + dst + ", Source MAC: " + src
        #TODO unpacking IP header
        #unpacking.unpack_IP(mac_data)

main()