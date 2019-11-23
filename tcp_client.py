from TCPyPacket import TCPyPacket as pkt
import socket as s
import time
import argparse

MAX_BYTES = 1452

class TCPyClient:
    #                                  SEQUENCE VARIABLES
    ############################################################################################
    #  These are variables specified per RFC 793 for use in managing SEND and RCV sequencing.
    #  Their general use is described as:
    #       SENDING
    #        for any sequence number seq_num:
    #            if seq_num < SND.UNA - old sequence numbers already acknowledged
    #            if SND.UNA < seq_num < SND.NXT - sequence numbers sent but unacknowledged
    #            if SND.NXT < seq_num < SND.UNA + SND.WND - sequence numbers allowed for new transission
    #            if seq_num > SND.UNA + SND.WND - future sequence numbers not allowed
    #
    #       RECEIVING
    #        for any sequence number seq_num:
    #           if seq_num < RCV.NXT - old sequence numbers already acknowledged
    #           if RCV.NXT < seq_num < RCV.NXT + RCV.WND - sequenced numbers allowed for new reception
    #           if seq_num > RCV.NXT + RCV.WND - future sequence numbers not allowed
    ############################################################################################
    SEQ_VARS = {
        'SND.UNA' : 0,
        'SND.NXT' : 0,
        'SND.WND' : 0,
        'RCV.NXT' : 0, 
        'RCV.WND' : 0,
        'ISS'     : 0
    }


    # NOTE: RCV.NXT + RCV.WIND-1 = last seq number expected on incoming segment, right edge of receive window

    #                                  CURRENT SEGMENT VARIABLES
    ############################################################################################
    #  These are variables specified per RFC 793 for use in managing segments by taking their values from
    #  the fields of the current segment. Their general use is described as:
    #       
    ############################################################################################

    CURR_SEG_VARS = {
        'SEG.SEQ' : 'first segment sequence number',
        'SEG.ACK' : 'segment acknowledgement number',
        'SEG.LEN' : 'segment length',
        'SEG.WND' : 'segment window',
    }

    #       NOTE: SND.UNA < SEG.ACK <= SND.NXT = acceptable ack received by sender
    #             RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND 
    #                           OR                                     - valid receive sequence space
    #             RCV.NXT <= SEG.SEQ+SEG.LEN-1 < RCV.NXT + RCV.WND
    #             SEG.SEQ + SEG.LEN-1 = last sequence number of incoming segment
    #
    #       NOTE: if SYN then SEG.SEQ is considered the sequence number to synchronize

    
    CURR_STATE = 'CLOSED'

    

    def __init__(self, dest_address, source_port, dest_port, filename):
        self.FILENAME = filename
        self.file = open(filename, "rb")
        # create socket and apply the appropriate connection information
        self.sock = s.socket(s.AF_INET, s.SOCK_DGRAM)
        self.SOURCE_ADDRESS = s.gethostbyname(s.gethostname())
        self.DEST_ADDRESS = dest_address
        self.SOURCE_PORT = source_port
        self.DEST_PORT = dest_port
        self.SERVER = (self.DEST_ADDRESS, self.DEST_PORT)
        self.sock.bind(('', self.SOURCE_PORT))
        # set the time-based initial sequence number
        self.SEQ_VARS['ISS'] = int(time.time()) % 2**32-1

        # set up TCP states and handlers dictionary
        self.TCP_STATES = {
            'CLOSED': self.handle_closed,
            'SYN-SENT': self.handle_syn_sent,
            'ESTABLISHED': self.handle_established,
            'FIN-WAIT-1': self.handle_fin_wait_1,
            'FIN-WAIT-2': self.handle_fin_wait_2,
            'CLOSING': self.handle_closing,
            'TIME-WAIT': self.handle_time_wait,
        }

        self.unack_packets = {}

    #                               CONNECTION STATE HANDLERS
    ############################################################################################
    # function for handling CLOSED state operations and events - this is the usual starting state
    def handle_closed(self):
        print("Attempting to connect to {}:{}".format(self.DEST_ADDRESS, self.DEST_PORT))
        self.sock.connect(self.SERVER)
        if self.send_syn():
            self.SEQ_VARS['SND.UNA'] = self.SEQ_VARS['ISS'] # setting earliest sent unack to ISS
            self.SEQ_VARS['SND.NXT'] = self.SEQ_VARS['ISS'] + 1 # setting next seq num to send
            self.CURR_STATE = 'SYN-SENT'
            return
        # wasn't able to successfully send SYN
        else:
            print("ERROR({}): Unable to send SYN packet.".format(self.CURR_STATE))
            print("Shutting down client.")
            self.sock.close()
            exit(1)

    # function for handling SYN-SENT state operations and events
    def handle_syn_sent(self):
        try:
            bytes_packet, address = self.sock.recvfrom(4096)
            packet = pkt.unpack_packet(self.SOURCE_ADDRESS, self.DEST_ADDRESS, bytes_packet)
            if packet['ACK'] and packet['SYN']:
                if packet['ACK_NUM'] != self.SEQ_VARS['SND.NXT']:
                    print("ERROR({}): Wrong ACK for handshake.".format(self.CURR_STATE))
                    print("Shutting down client.")
                    self.sock.close()
                    exit(1)
                self.SEQ_VARS['SND.NXT'] = packet['ACK_NUM'] # ACK of 101 means expecting SEQ 101
                self.SEQ_VARS['RCV.WND'] = packet['WINDOW']
                self.send_ack(packet['SEQ_NUM'] + 1)
                self.unack_packets[packet['ACK_NUM']] = (None, time.time())
                self.SEQ_VARS['SND.UNA'] = packet['ACK_NUM']
                self.CURR_STATE = 'ESTABLISHED'
                return
        except s.timeout:
            print("ERROR({}): Timed out while waiting for ack to SYN.")
            print("Shutting down client.")
            self.sock.close()
            exit(1)

    # where the beef of the sending occurs
    def handle_established(self):
        # repeatedly send new packets to fill remaining window and retransmit timed out packets
        bytes_data = self.file.read()
        bytes_size = len(bytes_data)
        done = False
        while not done:
            # retransmit timed out packets
            retrans_pack = {k:v for (k, v) in self.unack_packets.items() if time.time() - v[1] > 0.5}
            for k, v in retrans_pack.items():
                try:
                    self.sock.sendall(v[0].bytes)
                    self.unack_packets[k] = (v[0], time.time())
                except s.timeout:
                    print("ERROR({}): Error retransmitting expired packet (seq = {}).".format(self.CURR_STATE, k))
                    print("Shutting down client.")
                    self.sock.close()
                    exit(1)

            # grab the next bytes available to send - may be nothing if we didn't get an increase in window size
            start_index = self.SEQ_VARS['SND.NXT'] - self.SEQ_VARS['ISS'] - 1
            end_index = (self.SEQ_VARS['SND.UNA'] + self.SEQ_VARS['RCV.WND']) - self.SEQ_VARS['ISS'] - 1
            if end_index >= bytes_size - 1:
                done = True
            new_size = end_index - start_index
            new_data = bytes_data[start_index : end_index]

            data_chunks = [new_data[i * MAX_BYTES : (i+1) * MAX_BYTES] for i in range((len(new_data) // MAX_BYTES))]
            for chunk in data_chunks:
                new_packet = pkt.package_packet(source_address=self.SOURCE_ADDRESS, dest_address=self.DEST_ADDRESS,
                                    source_port=self.SOURCE_PORT, dest_port=self.DEST_PORT, 
                                    seq_num=self.SEQ_VARS['SND.NXT'], data=chunk)
                # send the packets and handle errors
                try:
                    start_time = time.time()
                    self.sock.sendall(new_packet.bytes)
                    # update SND.NXT and add packet to list of unack'ed packets with timer
                    self.SEQ_VARS['SND.NXT'] += len(chunk)
                    self.unack_packets[self.SEQ_VARS['SND.NXT']] = (new_packet, start_time)
                    
                except s.timeout:
                    print("ERROR({}): Error sending packet (seq = {}).".format(self.CURR_STATE, self.SEQ_VARS['SND.NXT']))
                    print("Shutting down client.")
                    self.sock.close()
                    exit(1)
            if done:
                if not self.send_fin():
                    print("ERROR({}): Error sending FIN.")
                    print("Shutting down client.")
                    self.sock.close()
                    exit(1)
                self.CURR_STATE = 'FIN-WAIT-1'
                return
            
            # wait for ACKs - we've sent everything we can and there's nothing to do until then
            bytes_packet, address = self.sock.recvfrom(4096)
            rec_packet = pkt.unpack_packet(self.SOURCE_ADDRESS, self.DEST_ADDRESS, bytes_packet)
            if not rec_packet or not rec_packet.get('ACK'):
                print("ERROR({}): Packet received was not an ACK.")
                continue
            self.unack_packets.pop(rec_packet['ACK_NUM'])
            if self.unack_packets:
                self.SEQ_VARS['SND.UNA'] = min(self.unack_packets, key=self.unack_packets.get) # update SND.UNA to oldest unack left
            self.SEQ_VARS['RCV.NXT'] = rec_packet['ACK_NUM'] # RCV.NXT updated to next expected seg
            self.SEQ_VARS['RCV.WND'] = rec_packet['WINDOW']
        return
    # handler for FIN-WAIT-1 state - the state which handles all unack'ed packets and waits for FIN or ACK of FIN back
    def handle_fin_wait_1(self):
        while self.unack_packets:
            # retransmit timed out packets
            retrans_pack = {k:v for (k, v) in self.unack_packets.items() if time.time() - v[1] > 0.5}
            for k, v in retrans_pack.items():
                try:
                    self.sock.sendall(v[0].bytes)
                    unack_packets[k] = (v[0], time.time())
                except s.timeout:
                    print("ERROR({}): Error retransmitting expired packet (seq = {}).".format(self.CURR_STATE, k))
                    print("Shutting down client.")
                    self.sock.close()
                    exit(1)
            # wait for ACKs
            bytes_packet, address = self.sock.recvfrom(4096)
            rec_packet = pkt.unpack_packet(self.SOURCE_ADDRESS, self.DEST_ADDRESS, bytes_packet)
            if not rec_packet or not rec_packet.get('ACK'):
                print("ERROR({}): Packet received was not an ACK.")
                continue
            self.unack_packets.pop(rec_packet['ACK_NUM'])
        # all packets ACK
        self.CURR_STATE = 'DONE'
        return
    # handler for FIN-WAIT-2 state - handles receiving a FIN from server
    def handle_fin_wait_2(self):
        return
    def handle_time_wait(self):
        return
    def handle_closing(self):
        return

    def send_fin(self):
        packet = pkt.package_packet(source_address=self.SOURCE_ADDRESS, dest_address=self.DEST_ADDRESS,
                                    source_port=self.SOURCE_PORT, dest_port=self.DEST_PORT, 
                                    seq_num=self.SEQ_VARS['SND.NXT'], fin=True)
        try:
            self.sock.sendall(packet.bytes)
            return True
        except s.timeout:
            return False

    def send_syn(self):
        packet = pkt.package_packet(source_address=self.SOURCE_ADDRESS, dest_address=self.DEST_ADDRESS,
                                    source_port=self.SOURCE_PORT, dest_port=self.DEST_PORT, 
                                    seq_num=self.SEQ_VARS['ISS'], syn=True)
        try:
            self.sock.sendall(packet.bytes)
            return True
        except s.timeout:
            return False
    
    def send_ack(self, num_to_ack):
        packet = pkt.package_packet(source_address=self.SOURCE_ADDRESS, dest_address=self.DEST_ADDRESS,
                                       source_port=self.SOURCE_PORT, dest_port=self.DEST_PORT, 
                                       seq_num=self.SEQ_VARS['SND.NXT'], ack_num=num_to_ack,
                                       ack=True, window=0)
        try:
            self.sock.sendall(packet.bytes)
            return True
        except s.timeout:
            return False

    def send(self):
        print("SENDING: File = {} To: {}:{}".format(self.FILENAME, self.DEST_ADDRESS, self.DEST_PORT))
        while self.CURR_STATE != 'DONE':
            self.TCP_STATES[self.CURR_STATE]()
            
        print("Done sending, closing connection.")
        self.sock.close()
        return

class Main:
    
    # Parsing for argument flags
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", required=True, type=str, help="supply a destination address")
    parser.add_argument("-f", required=True, type=str, help="supply a filename in string format")
    parser.add_argument("-cp", required=True, type=int, help="supply client port information")
    parser.add_argument("-sp", required=True, type=int, help="supply server port information")

    args = parser.parse_args()

    # setting server address and outputting value set to console
    SERVER_ADDRESS = args.a
    print("Server address:", SERVER_ADDRESS)
    # setting filename and outputting value set to console
    FILENAME = args.f
    print("Filename:", FILENAME)
    # checking for appropriate port numbers
    # *** THIS IS MUCH PRETTIER THAN USING choices=range(5000, 65535) in add_argument()!!!!!!! ***
    if args.cp < 5000 or args.cp > 65535:
        parser.exit(message="\tERROR(args): Client port out of range\n")
    CLIENT_PORT = args.cp
    print("Client port:", CLIENT_PORT)
    # checking for appropriate server port numbers
    if args.sp < 5000 or args.sp > 65535:
        parser.exit(message="\tERROR(args): Server port out of range\n")
    SERVER_PORT = args.sp
    print("Server port:", SERVER_PORT)
    
    tcp_client = TCPyClient(SERVER_ADDRESS, CLIENT_PORT, SERVER_PORT, FILENAME)
    tcp_client.send()

"""
    source_address = "0.0.0.0"
    dest_address = "1.1.1.1"
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
    
    packet = pkt.package_packet(source_address=source_address, dest_address=dest_address,
                                       source_port=source_port, dest_port=dest_port, 
                                       seq_num=seq_num, ack_num=ack_num, offset=offset, 
                                       ack=ack, syn=syn, fin=fin, window=window, data=data)
"""