import struct, binascii, formatting

# LAYER 2 : DATA LINK LAYER 

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


# LAYER 3: NETWORK

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


# LAYER 4: TRANSPORT 
#TODO