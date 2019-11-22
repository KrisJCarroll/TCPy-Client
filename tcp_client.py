from TCPyPacket import TCPyPacket as pkt
import socket as s
import sys

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
        'SND.UNA' : 'send unacknowledged',
        'SND.NXT' : 'send next',
        'SND.WND' : 'send window',
        'SND.UP'  : 'send urgent pointer',
        'SND.WL1' : 'seg. seq. num for last window',
        'SND.WL2' : 'seg. ack num for last window',
        'ISS'     : 'initial send sequence number'
    }

    REC_SEQ_VARS = {
        'RCV.NXT' : 'receive next',
        'RCV.WND' : 'receive window',
        'RCV.UP'  : 'receive urgent pointer',
        'IRS'     : 'intial receive seq. num'
    }

    #                                  CURRENT SEGMENT VARIABLES
    ############################################################################################
    #  These are variables specified per RFC 793 for use in managing segments by taking their values from
    #  the fields of the current segment. Their general use is described as:
    #       
    ############################################################################################

    CURR_SEG_VARS = {
        'SEG.SEQ' : 'segment sequence number',
        'SEG.ACK' : 'segment acknowledgement number',
        'SEG.LEN' : 'segment length',
        'SEG.WND' : 'segment window',
        'SEG.UP'  : 'segment urgent pointer',
        'SEG.PRC' : 'segment precedence value'
    }

    #                               CONNECTION STATES
    ############################################################################################
    TCP_STATES = {
        'LISTEN'  : 'waiting for connection request from any remote TCP and port',
        'SYN-SENT': 'waiting for matching connection request after sending connection request',
        'SYN-RECV': 'waiting for a confirming connection request ack after having both received and sent a connect request',
        'ESTABLISHED': 'connection is open, data received delivered to user - normal state for data transfer phase',
        'FIN-WAIT-1': 'waiting for connection termination request from remote TCP or ack of previous termination request',
        'FIN-WAIT-2': 'waiting for a connection termination request from remote TCP',
        'CLOSE-WAIT': 'waiting for a connection termination request from local user',
        'CLOSING': 'waiting for a connection termination request ack from remote TCP',
        'LAST-ACK': 'waiting for acknowledgement of connection termination request previously sent to remote TCP',
        'TIME-WAIT': 'waiting for enough time to pass to be sure remote TCP received ack of its connection term request',
        'CLOSED': 'no connection state at all'
    }


    def __init__(self, source_port = 0, dest_port = 0):
        self.source_port = source_port
        self.dest_port = dest_port

class Main:
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