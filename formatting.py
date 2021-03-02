import binascii

# MAC address formatting
def MAC(i):
    return '-'.join(a+b for a,b in zip(i[::2], i[1::2]))

# IPv4 address formatting
def IPv4(i):
    addr = str(i[0])
    for k in range (1,4):
        addr = addr + "."+str(i[k])
    return addr

# convert bytes to hexadecimal 
def b2hex(i):
    return binascii.hexlify(i).upper()