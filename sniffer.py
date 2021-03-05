import pcap, unpacking, ports_types

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
    net_prot = ports_types.get_network_prot(ethertype)
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
        trans_prot = ports_types.get_transport_prot(protocol)
        if(trans_prot == "TCP"):
            print("Transport Layer: TCP")
            src,dst,seqnum,acknum,offset,syn,ack,fin,window,app_payload = unpacking.unpack_TCP(payload)
            print "     Source port: " + str(src)
            print "     Destination port: " + str(dst)
            app_prot_src = ports_types.port_protocol(src)
            app_prot_dst = ports_types.port_protocol(dst)
            if(app_prot_dst != "None"):
                print "     Application Layer Protocol: " + str(app_prot_dst)
            elif(app_prot_src != "None"):
                 print "     Application Layer Protocol: " + str(app_prot_src)
            print "     Sequence Number: " + str(seqnum)
            print "     SYN: " + str(syn)
            print "     FIN: " + str(fin)
            print "     ACK: " + str(ack)
            print "     Acknowledgement Number: " + str(acknum)
            print "     Header Length: " + str(offset) +" bytes"
            print "     Window: " + str(window)
        if(trans_prot == "UDP"):
            print("Transport Layer: UDP")
            src,dst,length = unpacking.unpack_UDP(payload)
            print "     Source port: " + str(src)
            print "     Destination port: " + str(dst)
            print "     Length: " + str(length)
            app_prot_src = ports_types.port_protocol(src)
            app_prot_dst = ports_types.port_protocol(dst)
            if(app_prot_dst != "None"):
                print "     Application Layer Protocol: " + str(app_prot_dst)
            elif(app_prot_src != "None"):
                 print "     Application Layer Protocol: " + str(app_prot_src)
        if(trans_prot == "IGMP"):
            print("Transport Layer: IGMP")
            version_type, group_addr = unpacking.unpack_IGMP(payload)
            print "     Message Type: " + version_type
            print "     Group Address: " + str(group_addr)
    elif(net_prot == "ARP"): 
        print("Network Layer: ARP")
        src_mac,dst_mac,src_ip,dst_ip,htype,optype,ether = unpacking.unpack_ARP(mac_data)
        print "     Source MAC: " + src_mac
        print "     Source IP: " + src_ip
        print "     Destination MAC: " + dst_mac
        print "     Destination IP: " + dst_ip
        print "     Hardware Type: " + htype
        print "     Operation: " + optype
        print "     Ethertype: " + ether

main()