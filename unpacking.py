import struct, binascii

def formatting_MAC(i):
    return '-'.join(a+b for a,b in zip(i[::2], i[1::2]))

def hex(i):
    return binascii.hexlify(i).upper()

def unpack_MAC(data):
    dst, src , proto = struct.unpack('!6s6s2s',data[:14]) 
    dst_hex = hex(dst)
    src_hex = hex(src)
    #return destination and source in hexadecimal, and the rest of the packet
    return formatting_MAC(dst_hex), formatting_MAC(src_hex), data[14:]

def unpack_IP(data):
    src, dst= struct.unpack('!12x4s4s',data[:20]) 
    #TODO format IP addresses

#TODO unpack transport layer