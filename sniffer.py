import pcap, unpacking

def main():
    cap = pcap.pcap(None)
    print('listening on %s: %s' % (cap.name, cap.filter))
    print("--------------------------------------------------------------------------------------")
    
    #Support for IPv4 packets
    i = 1
    for d, packet in cap:
        #unpacking MAC (Ethernet) header
        dst, src, ethertype, mac_data = unpacking.unpack_MAC(packet)
        #print packet length in bytes
        print("Packet #"+str(i) +" Length = "+str(len(packet)))
        print "Destination MAC: " + dst + ", Source MAC: " + src


        if(ethertype == int('0800',16)): #IPv4
            print("Network Layer protocol: IPv4")
            #unpacking IP header
            dst, src = unpacking.unpack_IPv4(mac_data)
            print "Destination IP: " + str(dst) + ", Source IP: " + str(src)
        
        i = i+1
        print("--------------------------------------------------------------------------------------")

main()