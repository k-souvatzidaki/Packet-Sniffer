import struct, binascii, formatting, ports_types

# ============== LAYER 2: DATA LINK ================
# MAC 
# Header format: 
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |   MAC dst(48 bits)  |  MAC src(48 bits)  | Ethertype(16 bits) |
def unpack_MAC(data):
    #unpack the MAC header
    dst, src , ethertype = struct.unpack('!6s6s2s',data[:14]) 
    dst_hex = formatting.b2hex(dst)
    src_hex = formatting.b2hex(src)
    #return destination and source in hexadecimal, ethertype as an intiger and the MAC payload
    return formatting.MAC(dst_hex), formatting.MAC(src_hex), int(formatting.b2hex(ethertype),16), data[14:]


# ============== LAYER 3: NETWORK ================
# IPv4
# Header format: 
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |       Version|IHL|DSCP|ECN|Total Length (32 bits total)       |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |           ID|Flags|Fragment offset (32 bits total)            |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |                       Src IP (32 bits)                        |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |                       Dst IP (32 bits)                        |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |                 Options if IHL > 5 (32 bits)                  |
def unpack_IPv4(data):
    #unpack the IPv4 header
    version_length, total_length, ttl, protocol, src, dst= struct.unpack('!sx2s4xss2x4s4s',data[:20]) 
    #version and length
    version_length = formatting.b2hex(version_length)
    version = str(version_length)[0]
    length_bytes = int(str(version_length[1]),16) * 4
    #total length
    total_length = int(formatting.b2hex(total_length),16)
    #time to live
    ttl = int(formatting.b2hex(ttl),16)
    #encapsulated protocol
    protocol = formatting.b2hex(protocol)
    #formatting ip addresses
    src = formatting.IPv4(struct.unpack('{}B'.format(len(src)),src))
    dst = formatting.IPv4(struct.unpack('{}B'.format(len(dst)),dst))
    #the payload (depends on variable header length)
    payload = data[length_bytes:]
    #return
    return  version, length_bytes, total_length, ttl, protocol, src, dst, payload

# ARP
# Header format: 
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |      Hardware(16 bits)    |       Ethertype (16 bits)         |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# | HLength(8 bits) | PLength(8 bits) |    Operation (16 bits)    |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |                     Sender MAC (48 bits)                      |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |                      Sender IP (32 bits)                      |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |                     Target MAC (48 bits)                      |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |                      Target IP (32 bits)                      |
def unpack_ARP(data): 
    hardware_type, ethertype, operation, src_mac, src_ip, dst_mac, dst_ip = struct.unpack('!2s2s2x2s6s4s6s4s',data[:28]) 
    src_mac = formatting.MAC(formatting.b2hex(src_mac))
    dst_mac = formatting.MAC(formatting.b2hex(dst_mac))
    src_ip = formatting.IPv4(struct.unpack('{}B'.format(len(src_ip)),src_ip))
    dst_ip = formatting.IPv4(struct.unpack('{}B'.format(len(dst_ip)),dst_ip))
    htype = ports_types.ARP_HTYPE(int(formatting.b2hex(hardware_type),16))
    optype = ports_types.ARP_OPERATION(int(formatting.b2hex(operation),16))
    ether = ports_types.get_network_prot(int(formatting.b2hex(ethertype),16))
    return src_mac,dst_mac,src_ip,dst_ip,htype,optype,ether


# ============== LAYER 4: TRANSPORT ================
# TCP
# Header format: 
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |      Src Port(16 bits)    |        Dst Port (16 bits)         |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |                  Sequence Number (32 bits)                    |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |                    ACK number (32 bits)                       |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# | Data Offset (4)| Reserved&Flags (12)|     Window Size (16)    |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |      Checksum (16 bits)    |         Urgent (16 bits)         |
def unpack_TCP(data):
    src, dst, seqnum, acknum, offset,flags,window = struct.unpack('!HHIIssH',data[:16])
    #TODO add more fields
    offset = int(str(formatting.b2hex(offset))[0],16) * 4
    flags = bin(int(str(formatting.b2hex(flags)),16)).lstrip('0b')
    if(len(flags) < 5):
        ack = "0"
    else:
        ack = flags[len(flags)-5]
    if(len(flags) < 2):
        syn = "0"
    else:
        syn = flags[len(flags)-2]
    if(len(flags) == 0):
        fin = "0"
    else: 
        fin = flags[len(flags)-1]
    return src,dst,seqnum,acknum,offset,syn,ack,fin,window,data[offset:]

# UDP
# Header format:
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |      Src Port(16 bits)      |       Dst Port (16 bits)        |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |       Length (16 bits)      |       Checksum (16 bits)        |
def unpack_UDP(data):
    #unpack the UDP header
    src, dst,length = struct.unpack('!HHH2x',data[:8])
    return src,dst,length

# IGMP
# Header format:
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# | Version/Type (8 bits)| Max Resp (8 bits) | Checksum (16 bits) |
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |                   Group Address (32 bits)                     |
# **Max Resp = Unused in v1
def unpack_IGMP(data):
    #unpack the IGMP header
    version_type, group_addr = struct.unpack('!s3x4s',data[:8]) 
    #version and type
    version_type = formatting.b2hex(version_type)
    #group address
    group_addr = formatting.IPv4(struct.unpack('{}B'.format(len(group_addr)),group_addr))
    return ports_types.IGMP_type(version_type),group_addr