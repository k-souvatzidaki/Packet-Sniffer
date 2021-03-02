import pcap, unpacking

def main():
    cap = pcap.pcap(None)
    print('Listening on %s: %s' % (cap.name, cap.filter))
    print("============================================================================")
    i = 1
    for d, packet in cap:
        print("Packet #"+str(i) +" Length = "+str(len(packet)))
        unpack(packet)
        i = i+1
        

def unpack(packet):
    #unpacking MAC (Ethernet) header
    dst, src, ethertype, mac_data = unpacking.unpack_MAC(packet)
    print "Destination MAC: " + dst + ", Source MAC: " + src
    print("-------------------------------------------------------------------------")

    #IPv4
    if(ethertype == int('0800',16)):
        print("Network Layer protocol: IPv4")
        #unpacking IP header
        version, length_bytes, total_length, ttl, protocol, src, dst, payload = unpacking.unpack_IPv4(mac_data)
        print "Version: "+str(version)
        print "Header length: "+str(length_bytes)+" bytes"
        print "Total length: "+str(total_length)+ " bytes"
        print "Time to Live: "+str(ttl)
        print "Destination IP: " + str(dst)
        print "Source IP: " + str(src)

        #TCP
        print protocol
        #if(protocol = int())

    print("============================================================================")

main()