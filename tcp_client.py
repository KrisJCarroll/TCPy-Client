from TCPyPacket import TCPyPacket as pkt

class TCPyClient:
    def __init__(self, source_port = 0, dest_port = 0):
        self.source_port = source_port
        self.dest_port = dest_port

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
    data = b'24'
    
    packet = pkt.package_packet(source_port=source_port, dest_port=dest_port, 
                                       seq_num=seq_num, ack_num=ack_num, offset=offset, 
                                       ack=ack, syn=syn, fin=fin, window=window, data=data)
    print(packet.bin)
    print("Hello world.")