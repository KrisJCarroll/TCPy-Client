"""
TCPy-Packet.py
Author: Kristopher Carroll
Last Modified: 11/13/2019

This module is for managing the TCP packet needs for the TCPy client. The module is
primarily responsible for forming TCP packet headers according to the specification
of RFC 793 matching the following format:

--------------------------------------------------------
|  Source Port (16 bits)    |   Dest. Port (16 bits)   |
--------------------------------------------------------
|                Sequence Number (32 bits)             |
--------------------------------------------------------
|                 Ack. Number (32 bits)                |  * indicates the sequence number sender expects to receive
--------------------------------------------------------
|Offset(4)|Reserved(6)|U|A|P|R|S|F|     Window(16)     |  * U|A|P|R|S|F are each 1 bit
--------------------------------------------------------
|   Checksum (16 bits)      |      Urgent Pointer(16)  |
--------------------------------------------------------
|             Options (24 bits)      | Padding (8 bits)|
--------------------------------------------------------
|                 Data (up to 1448 bytes)              |
--------------------------------------------------------
"""
import crccheck.checksum as cs
import bitstring as bs
from bitstring import BitArray
from bitstring import BitStream


class TCPyPacket:

    def calc_checksum(packet):
        # ensure checksum is 0'ed out
        packet.overwrite(b'\x00\x00', 128)
        checksum = cs.Checksum16.calcbytes(packet.tobytes())
        packet.overwrite(checksum, 128)

    def package_packet(source_port, dest_port, seq_num, ack_num, 
                       offset = 0, ack = False, syn = False, fin = False, 
                       window = 0, data = 0):

        packet_dict = {'source_port': source_port, 'dest_port': dest_port,
                       'seq_num': seq_num,
                       'ack_num': ack_num,
                       'offset': offset, 'reserved': 0, 'U': False, 'A': ack, 'P': False,  'R': False, 'S': syn, 'F': fin, 'window': window,
                       'checksum': b'\x00\x00', 'urgent': 0,
                       'options': 0, 
        }

        pack_format  = 'uint:16=source_port, uint:16=dest_port,'
        pack_format += ' uint:32=seq_num,'
        pack_format += ' uint:32=ack_num,'
        pack_format += ' uint:4=offset, uint:6=reserved, bool=U, bool=A, bool=P, bool=R, bool=S, bool=F, uint:16=window,'
        pack_format += ' bytes:2=checksum, uint:16=urgent,'
        pack_format += ' uint:24=options, pad:6,'
        header_binary = bs.pack(pack_format, **packet_dict)

        data_binary = BitStream(bytes=data)

        # combine the header and the data and fill out checksum
        packet = header_binary + data_binary
        print(packet.bin)
        TCPyPacket.calc_checksum(packet)
        print(packet.bin)

        return packet

class Main:

    source_port = 1007
    dest_port = 2008
    seq_num = 1000984
    ack_num = 1111111
    offset = 0
    ack = False
    syn = True
    fin = False
    window = 4000
    
    packet = TCPyPacket.package_packet(source_port=source_port, dest_port=dest_port, 
                                       seq_num=seq_num, ack_num=ack_num, offset=offset, 
                                       ack=ack, syn=syn, fin=fin, window=window)
    print(packet.bin)