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
|                 Ack. Number (32 bits)                |
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

class TCPyPacket:
    
    def package_packet(source_port, dest_port, seq_num, 
                       ack_num, offset = 0, syn = False, 
                       window = None, checksum = None, data = None):
        return

