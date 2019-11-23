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
import sys
import crccheck.checksum as cs
import bitstring as bs
import socket
from bitstring import BitArray
from bitstring import BitStream


class TCPyPacket:
    TCP_PTCL = (6).to_bytes(1, byteorder="big")

    def calc_checksum(packet, pseudo_header):
        # ensure checksum is 0'ed out
        packet.overwrite(b'\x00\x00', 128)
        cs_calc = cs.Checksum16()
        cs_calc.process(packet.tobytes())
        #cs_calc.process(pseudo_header)
        checksum = cs_calc.finalbytes()
        packet.overwrite(checksum, 128)

    def valid_checksum(bytes_packet, source_address, dest_address):
        bin_packet = BitStream(bytes_packet)
        length = len(bin_packet) % 8
        checksum = bin_packet[128:144].bytes
        pseudo_header = TCPyPacket.create_pseudo_header(source_address, dest_address, length)
        bin_packet.overwrite(b'\x00\x00', 128)
        cs_calc = cs.Checksum16()
        cs_calc.process(bin_packet.tobytes())
        #cs_calc.process(pseudo_header)
        if checksum != cs_calc.finalbytes():
            return False
        return True

    def create_pseudo_header(source_address, dest_address, length):
        pseudo_header  = bytearray()
        pseudo_header += bytearray(socket.inet_aton(source_address))
        pseudo_header += bytearray(socket.inet_aton(dest_address))
        pseudo_header += bytearray(b'\x00')
        pseudo_header += bytearray(TCPyPacket.TCP_PTCL) 
        pseudo_header += length.to_bytes(2, byteorder="big")
        return pseudo_header

    def unpack_packet(source_address, dest_address, bytes_packet):
        packet_binary = BitStream(bytes_packet)
        if not TCPyPacket.valid_checksum(source_address, dest_address, bytes_packet):
            return None
        packet_dict = {
            'S_PORT' : packet_binary[0:16].int,
            'D_PORT' : packet_binary[16:32].int,
            'SEQ_NUM': packet_binary[32:64].int,
            'ACK_NUM': packet_binary[64:96].int,
            'OFFSET' : packet_binary[96:100].int,
            'ACK'    : packet_binary[107],
            'SYN'    : packet_binary[110],
            'FIN'    : packet_binary[111],
            'WINDOW' : packet_binary[112:128],
        }
        return packet_dict

    # returns syn/ack'ed seq number and ack number if SYN and ACK set, else returns (False, False)
    def check_synack(packet_bytes):
        packet_binary = BitStream(bytes=packet_bytes)
        try:
            if packet_binary[110] and packet_binary[107]:
                seq_binary = packet_binary[32:64]
                ack_binary = packet_binary[64:96]
                seq_num = seq_binary.int
                ack_num = ack_binary.int
                return (seq_num, ack_num)
            return (False, False)
        except:
            return (False, False)

    def is_fin(packet_bytes):
        packet_binary = BitStream(bytes=packet_bytes)
        return packet_binary[111]

    def package_packet(source_address, dest_address, source_port, dest_port, seq_num, ack_num = 0, 
                       offset = 5, ack = False, syn = False, fin = False, 
                       window = 0, data = BitStream()):
        packet_dict = {'source_port': source_port, 'dest_port': dest_port,
                       'seq_num': seq_num,
                       'ack_num': ack_num,
                       'offset': offset, 'reserved': 0, 'U': False, 'A': ack, 'P': False,  'R': False, 'S': syn, 'F': fin, 'window': window,
                       'checksum': b'\x00\x00', 'urgent': 0,
        }

        pack_format  = 'uint:16=source_port, uint:16=dest_port,'
        pack_format += ' uint:32=seq_num,'
        pack_format += ' uint:32=ack_num,'
        pack_format += ' uint:4=offset, uint:6=reserved, bool=U, bool=A, bool=P, bool=R, bool=S, bool=F, uint:16=window,'
        pack_format += ' bytes:2=checksum, uint:16=urgent,'
        header_binary = bs.pack(pack_format, **packet_dict)
        # combine the header and the data binary
        data_binary = BitStream(bytes=data)
        packet = header_binary + data_binary
        # no data

        length = len(packet) % 8
        pseudo_header = TCPyPacket.create_pseudo_header(source_address, dest_address, length)


        TCPyPacket.calc_checksum(packet, pseudo_header)

        return packet

