import struct, binascii, formatting

# LAYER 2 : DATA LINK LAYER - MAC 
# Header format: 
#  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
# |   MAC dst(48 bits)  |  MAC src(48 bits)  | Ethertype(16 bits) |

def unpack_MAC(data):
    #unpack the MAC header
    dst, src , ethertype = struct.unpack('!6s6s2s',data[:14]) 
    dst_hex = formatting.hex(dst)
    src_hex = formatting.hex(src)
    #return destination and source in hexadecimal, ethertype as an intiger and the MAC payload
    return formatting.MAC(dst_hex), formatting.MAC(src_hex), int(formatting.hex(ethertype),16), data[14:]


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
    src, dst= struct.unpack('!12x4s4s',data[:20]) 
    formatted_src = formatting.IPv4(struct.unpack('{}B'.format(len(src)),src))
    formatted_dst = formatting.IPv4(struct.unpack('{}B'.format(len(dst)),dst))
    #return formatted destination and source
    return formatted_src,formatted_dst


# LAYER 4: TRANSPORT 
#TODO