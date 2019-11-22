from TCPyPacket import TCPyPacket as pkt
import socket as s
import time
import argparse

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
    SEND_SEQ_VARS = {
        'SND.UNA' : 'first unacknowledged',
        'SND.NXT' : 'send next',
        'SND.WND' : 'send window',
        'SND.UP'  : 'send urgent pointer',
        'SND.WL1' : 'seg. seq. num for last window',
        'SND.WL2' : 'seg. ack num for last window',
        'ISS'     : 'initial send sequence number'
    }

    REC_SEQ_VARS = {
        'RCV.NXT' : 'next seq num expected', # left edge of receive window
        'RCV.WND' : 'receive window',
        'RCV.UP'  : 'receive urgent pointer',
        'IRS'     : 'intial receive seq. num'
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
        'SEG.UP'  : 'segment urgent pointer',
        'SEG.PRC' : 'segment precedence value'
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
        self.filename = filename
        # create socket and apply the appropriate connection information
        self.sock = s.socket(s.AF_INET, s.SOCK_STREAM)
        self.sock.settimeout(1)
        self.SOURCE_ADDRESS = s.gethostbyname(s.gethostname())
        self.DEST_ADDRESS = dest_address
        self.SOURCE_PORT = source_port
        self.DEST_PORT = dest_port
        self.SERVER = (DEST_ADDRESS, DEST_PORT)
        # connect to the server
        self.sock.connect(self.SERVER)
        # set the time-based initial sequence number
        self.SEND_SEQ_VARS['ISS'] = int(time.time()) % 2**32 

        # set up TCP states and handlers dictionary
        self.TCP_STATES = {
            'SYN-SENT': self.handle_syn_sent,
            'ESTABLISHED': self.handle_established,
            'FIN-WAIT-1': self.handle_fin_wait_1,
            'FIN-WAIT-2': self.handle_fin_wait_2,
            'CLOSING': self.handle_closing,
            'TIME-WAIT': self.handle_time_wait,
            'CLOSED': self.handle_closed
        }

    #                               CONNECTION STATE HANDLERS
    ############################################################################################
    # function for handling CLOSED state operations and events - this is the usual starting state
    def handle_closed(self):
        if self.send_syn():
            self.SEND_SEQ_VARS['SND.UNA'] = self.SEND_SEQ_VARS['ISS'] # setting earliest sent unack to ISS
            self.SEND_SEQ_VARS['SND.NXT'] = self.SEND_SEQ_VARS['ISS'] + 1 # setting next seq num to send
            self.CURR_STATE = 'SYN_SENT'
            return
        # wasn't able to successfully send SYN
        else:
            print("ERROR({}): Unable to send SYN packet.".format(self.CURR_STATE))
            print("Shutting down client.")
            self.sock.close()
            exit(1)

    # function for handling SYN-SENT state operations and events
    def handle_syn_sent(self):
        timeouts = 0
        while timeouts < 3:
            try:
                bytes_packet = self.sock.recv(1500)
                packet = pkt.unpack_packet(bytes_packet)
                if packet['ACK'] and packet['SYN']:
                    if packet['ACK_NUM'] != self.SEND_SEQ_VARS['SND.UNA']:
                        print("ERROR({}): Wrong ACK for handshake.".format(self.CURR_STATE))
                        print("Shutting down client.")
                        self.sock.close()
                        exit(1)
                    self.REC_SEQ_VARS['REC.WND'] = packet['WINDOW']
                    self.CURR_STATE = 'ESTABLISHED'
                    return
            except s.timeout:
                timeouts += 1
        print("ERROR({}): Timed out while waiting for ack to SYN.")
        print("Shutting down client.")
        self.sock.close()
        exit(1)

    # where the beef of the sending occurs
    def handle_established(self):
        return
    def handle_fin_wait_1(self):
        return
    def handle_fin_wait_2(self):
        return
    def handle_time_wait(self):
        return
    def handle_closing(self):
        return

    def send_syn(self):
        timeouts = 0
        packet = pkt.package_packet(source_address=self.SOURCE_ADDRESS, dest_address=self.DEST_ADDRESS,
                                    source_port=self.source_port, dest_port=self.dest_port, 
                                    seq_num=self.SEND_SEQ_VARS['ISS'], ack_num=0,
                                    syn=True)
        while timeouts < 3:
            try:
                self.sock.sendall(packet)
                return True
            except s.timeout:
                timeouts +=1
        return False
    
    def send_ack(self):
        packet = pkt.package_packet(source_address=self.SOURCE_ADDRESS, dest_address=self.DEST_ADDRESS,
                                       source_port=self.source_port, dest_port=self.dest_port, 
                                       seq_num=self.SEND_SEQ_VARS['SND.NXT'], ack_num=num_to_ack,
                                       syn=True, window=0)

    def send(self, data):
        while True:
            return

class Main:
    """
    # Parsing for argument flags
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", required=True, type=str, help="supply a destination address")
    parser.add_argument("-f", required=True, type=str, help="supply a filename in string format")
    parser.add_argument("-cp", required=True, type=int, help="supply client port information")
    parser.add_argument("-sp", required=True, type=int, help="supply server port information")
    parser.add_argument("-m", required=True, choices=['r', 'w'], help="choose either (r)ead or (w)rite mode")

    args = parser.parse_args()

    # setting server address and outputting value set to console
    SERVER_ADDRESS = args.a
    print("Server address:", SERVER_ADDRESS)
    # setting filename and outputting value set to console
    FILENAME = args.f
    print("Filename:", FILENAME)
    # checking for appropriate port numbers
    # *** THIS IS MUCH PRETTIER THAN USING choices=range(5000, 65535) in add_argument()!!!!!!! ***
    if args.p < 5000 or args.p > 65535:
        parser.exit(message="\tERROR(args): Client port out of range\n")
    CLIENT_PORT = args.p
    print("Client port:", CLIENT_PORT)
    # checking for appropriate server port numbers
    if args.sp < 5000 or args.sp > 65535:
        parser.exit(message="\tERROR(args): Server port out of range\n")
    SERVER_PORT = args.sp
    print("Server port:", SERVER_PORT)
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
    print(packet.bin)
    print("Hello world.")