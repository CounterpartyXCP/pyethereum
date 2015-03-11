import binascii
import rlp

NULLSHA3 = binascii.unhexlify(b'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')  # TODO: Check

def compress(data):
    o = b''
    i = 0
    while i < len(data):
        if rlp.int_to_big_endian(data[i]) == b'\xfe':
            o += b'\xfe\x00'
        elif data[i:i + 32] == NULLSHA3:
            o += b'\xfe\x01'
            i += 31
        elif data[i:i + 2] == b'\x00\x00':
            p = 2
            while p < 255 and i + p < len(data) and rlp.int_to_big_endian(p) == b'\x00':
                p += 1
            o += b'\xfe' + rlp.int_to_big_endian(p)
            i += p - 1
        else:
            o += rlp.int_to_big_endian(data[i])
        i += 1
    return o


def decompress(data):
    o = b''
    i = 0
    while i < len(data):
        if rlp.int_to_big_endian(data[i])  == b'\xfe':
            if i == len(data) - 1:
                raise Exception("Invalid encoding, \\xfe at end")
            elif rlp.int_to_big_endian(data[i + 1]) == b'\x00':
                o += b'\xfe'
            elif rlp.int_to_big_endian(data[i + 1]) == b'\x01':
                o += NULLSHA3
            else:
                o += b'\x00' * data[i + 1]
            i += 1
        else:
            o += rlp.int_to_big_endian(data[i])
        i += 1
    return o
