import dpkt
import socket
import sys

# Caputure packets that are going on the wire
# both packets from the computer and to the computer
# TCPdump is a command-line tool that analyzes the packets captured on the wire.

# parse PCAP files.
# PCAP is the file format used to store packets captured on the wire.
# PCAP files are in binary format, parse it with library

# analysis_pcap_tcp
# analyzes PCAP file to characterize the TCP flows in the trace
# TCP flow starts with a TCP "SYN" and ends at a TCP "FIN"
    # between two hosts with a fixed IP address and ports
# There can be multiple TCP flows at the same time between two hosts, on different ports

# ---
# number of TCP flows initiated from the sender
# for each TCP flow
# first 2 transactions after the TCP connection is set up (from sender to reciever)
    # the values of the Sequence number, Ack number, Receive Window size
# sender throughput - total amount of data sent by the sender over the period of time 
    # period of time - sending the first byte to receiving the last acknowledgement
    # only consider packets at the TCP level (including the header), ignore all other headers and acks

class TCP_flow:
    def __init__(self, eth):
        self.ip = eth.data
        self.ip_src = self.ip.src
        self.ip_dst = self.ip.dst
        self.tcp = self.ip.data
        self.tcp_dport = self.tcp.dport
        self.tcp_sport = self.tcp.sport
        self.set_up = False
        self.syn_ack = False
        self.num_packets = 0
        self.packets = []
        self.prev_ack = None
        self.prev_seq = None
        self.start_time = None
        self.end_time = None
        self.total_data = 0
        self.packets_in_flight = 0
        self.packets_received = 0
        self.cwnd = []
        self.num_acks = 0
        self.duplicates = 0
        self.retransmissions = 0
        self.triple_dup_acks = 0
        self.timeouts = 0

def tcp_dump(filename, sender, receiver):
    # open pcap file        
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)
    # access each packet
    TCP_flows = []
    total_flows = 0
    # sender = b'\x82\xf5\x91\x0c' # '130.245.145.12'
    # receiver = b'\x80\xd0\x02\xc6' # '128.208.2.198'
    print("Sender:" , socket.inet_ntoa(sender), "| Receiver:" , socket.inet_ntoa(receiver))
    for timestamp, buf in pcap:
        # unpack Ethernet frame
        eth = dpkt.ethernet.Ethernet(buf)
        curr = TCP_flow(eth)

        if (curr.ip_src == sender): # sender -> receiver
            # new flow
            if ((curr.tcp.flags & 0x02) and curr.ip_src == sender): # SYN
                curr.start_time = timestamp
                total_flows += 1
                TCP_flows.append(curr)

            # find flow (x) that the packet is part of
            for x in TCP_flows:
                if (curr.tcp_sport == x.tcp_sport): # x = corresponding flow
                    # throughput
                    x.total_data = x.total_data + len(curr.tcp.data) + (curr.tcp.__hdr_len__)

                    # calculate transmissions
                    if (x.prev_seq != None and x.prev_seq > curr.tcp.seq):
                        x.retransmissions += 1
                    else:
                        x.prev_seq = curr.tcp.seq

                    if (x.duplicates >= 2):
                        # check next packet
                        if (x.prev_ack == curr.tcp.seq): 
                            x.triple_dup_acks += 1
                            x.duplicates = 0
                        
                    if (curr.tcp.flags & 0x01): # FIN                   
                        x.end_time = timestamp

                    break

        if (curr.tcp.flags & 0x10): # ACK (curr packet)
            for x in TCP_flows:
                if (curr.tcp_sport == x.tcp_sport or curr.tcp_dport == x.tcp_sport): # find flow (x) that the packet is part of 
                    if (x.set_up): # after the connection set up
                        x.num_packets += 1
                        if (x.num_packets <= 2): # for each flow, first two packets
                            option_list = dpkt.tcp.parse_opts(x.tcp.opts)
                            option_list = dict(option_list)
                            # receive window size = window size * window size scaling factor
                            receive_window_size = curr.tcp.win * (1 << (int.from_bytes(option_list[3], sys.byteorder)))  
                            # sequence number, ack number, receive window size       
                            x.packets.append([curr.tcp.seq, curr.tcp.ack, receive_window_size])

                    elif (curr.tcp.flags & 0x02): # SYN, ACK (curr packet)
                        x.syn_ack = True
                        break
                    elif ((not x.set_up) and x.syn_ack):
                        x.set_up = True
                        if (curr.ip_src == sender): # sender to receiver
                            x.packets_in_flight += 1
                        break

                    if (x.syn_ack): # calculate cwnd after SYN ACK (including ACK in 3 way handshake)
                        if (curr.ip_src == sender): # sender to receiver
                            x.packets_in_flight += 1
                            break
                        elif (curr.ip_src == receiver): # receiver to sender
                            if (x.cwnd == [] or (x.packets_received == x.cwnd[-1])):
                                x.cwnd.append(x.packets_in_flight)
                                x.packets_received = 0
                            x.packets_received += 1
                            x.packets_in_flight -= 1
                            # get first two acks
                            if (x.num_acks < 2):
                                option_list = dpkt.tcp.parse_opts(x.tcp.opts)
                                option_list = dict(option_list)
                                # receive window size = window size * window size scaling factor
                                receive_window_size = curr.tcp.win * (1 << (int.from_bytes(option_list[3], sys.byteorder)))  
                                ack = [curr.tcp.seq, curr.tcp.ack, receive_window_size]
                                x.packets[x.num_acks].append(ack)
                            x.num_acks += 1

                            # check triple duplicate acks, receiver -> sender
                            if (x.prev_ack == curr.tcp.ack):
                                x.duplicates += 1
                            else: 
                                x.prev_ack = curr.tcp.ack
                                x.duplicates = 0

                            break
    # ---
    print("The number of TCP flows initiated from the sender:" , total_flows)
    for x in TCP_flows:
        print("TCP Flow:")
        i = 0
        for y in x.packets:
            i += 1
            print("Packet", i, ": ", "Seq=", y[0], ", Ack=", y[1], ", Receive Window Size=", y[2], sep='')
            ack = y[3]
            print("\tACK Packet", i, ": ", "Seq=", ack[0], ", Ack=", ack[1], ", Receive Window Size=", ack[2], sep='')

        print("First 5 Congestion Window Sizes(cwnd):", x.cwnd[0:5])
        print("Sender Throughput:", (x.total_data/(x.end_time - x.start_time)), "bytes/second")
        print("Retransmissions:")
        print("\tTriple Duplicate Acks =", x.triple_dup_acks)
        x.timeouts = x.retransmissions - x.triple_dup_acks # calculated timeouts
        print("\tTimeouts =", x.timeouts)

class analysis_pcap_tcp:
    if (len(sys.argv) == 4):
        filename = sys.argv[1]
        sender = sys.argv[2]
        s = sender.split(".")
        num = b''
        for i in range(len(s)):
            s[i] = int(s[i]).to_bytes(1, 'big')
            num = num + s[i]
        sender = num
        receiver = sys.argv[3]
        r = receiver.split(".")
        num = b''
        for i in range(len(r)):
            r[i] = int(r[i]).to_bytes(1, 'big')
            num = num + r[i]
        receiver = num
        # sender and receiver will be passed in the function in byte format
        tcp_dump(filename, sender, receiver) 
        # tcp_dump('assignment2.pcap', b'\x82\xf5\x91\x0c', b'\x80\xd0\x02\xc6')
    else:
        print("Wrong arguments. 'filename' 'sender_ip' 'receiver_ip'")