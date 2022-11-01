from collections import Counter
import socket
import dpkt
import sys

# Hardcoded sender and receiver address
sender = '130.245.145.12'
receiver = '128.208.2.198'

# Getting TCP Flows
def tcpFlows(file_name):
    # read fileName through bytes
    file_name = open(file_name, 'rb')
    pcap = dpkt.pcap.Reader(file_name)

    tcp_flows = [] # tuple: (src port, src IP address, dest port, dest IP address)
    for _, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        
        # fin_flag = ( tcp.flags & 0x01 ) != 0
        syn_flag = ( tcp.flags & 0x02 ) != 0

        sport = tcp.sport # TCP Source Port #
        dport = tcp.dport # TCP Destination Port #

        if syn_flag: 
            existBool = False # boolean used to check if flow already been recorded
            
            # check for tcp flows in the tuple already
            for tcp_flow in tcp_flows: 
                if (sport == tcp_flow[0] or sport == tcp_flow[2]) and (dport == tcp_flow[0] or dport == tcp_flow[2]):
                    existBool = True
            # if does not exist in tuple, append to tuple
            if not existBool:
                tcp_flows.append((sport, sender, dport, receiver))

    return tcp_flows

# Getting First Two Transactions, Throughput, Period
def getTransactionsAndThroughput(file_name, tcp_flows):
    file_name = open(file_name, "rb")
    pcap = dpkt.pcap.Reader(file_name)

    num_of_handshakes = 3

    length_of_tcp_flows = len(tcp_flows)
    
    flow_count_trans = [0] * (length_of_tcp_flows) # initialize array, used to get transactions

    first_two_transactions = [[] for _ in range((length_of_tcp_flows) * 2)]
       
    temp = [-1] * (length_of_tcp_flows) # temp used to store length tcp info of flows used to get throughput and period
    first = [-1] * (length_of_tcp_flows) # the first pkt timestamp for each tcp flow
    last = [-1] * (length_of_tcp_flows) # the last pkt timestamp for each tcp flow

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        srcip = socket.inet_ntoa(ip.src)
        destip = socket.inet_ntoa(ip.dst)

        fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
        syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
       
        sport = tcp.sport
        dport = tcp.dport

        # GET FIRST TWO TRANSACTIONS (Part A.b)
        for i, tcp_flow in enumerate(tcp_flows): 
            if ((tcp_flow[0] == sport and tcp_flow[2] == dport) or (tcp_flow[0] == dport and tcp_flow[2] == sport)) and flow_count_trans[i] < num_of_handshakes:
                flow_count_trans[i] += 1
            else:
                if tcp_flow[0] == sport and tcp_flow[2] == dport:
                    if len(first_two_transactions[2 * i]) == 0: 
                        first_two_transactions[2 * i].append(f'| {srcip}:{sport} -> {destip}:{dport} | ({tcp.seq}, {tcp.ack}) |             {tcp.win}             |')
                    elif len(first_two_transactions[2 * i]) == 1:
                        first_two_transactions[2 * i].append(f'| {srcip}:{sport} -> {destip}:{dport} | ({tcp.seq}, {tcp.ack}) |             {tcp.win}             |')
                elif tcp_flow[0] == dport and tcp_flow[2] == sport:
                    if len(first_two_transactions[(2 * i) + 1]) == 0:
                        first_two_transactions[(2 * i) + 1].append(f'| {srcip}:{sport} -> {destip}:{dport} | ({tcp.seq}, {tcp.ack}) |             {tcp.win}             |')
                    elif len(first_two_transactions[(2 * i) + 1]) == 1:
                        first_two_transactions[(2 * i) + 1].append(f'| {srcip}:{sport} -> {destip}:{dport} | ({tcp.seq}, {tcp.ack}) |             {tcp.win}             |')

        # GET THROUGHPUT (Part A.c)
        for j, tcp_flow in enumerate(tcp_flows):
            if (sport == tcp_flow[0] and dport == tcp_flow[2]):
                temp[j] += len(tcp)
                if syn_flag:
                    first[j] = ts # timestamped first
                if fin_flag:
                    last[j] = ts # timestamped last

    throughputs = []
    for k, data in enumerate(temp):
        period = last[k] - first[k]
        throughput = (data / period)
        throughputs.append(throughput)
    
    return first_two_transactions, throughputs

# def congestionWindow(file_name, tcp_flows):
#     file_name = open(file_name, "rb")
#     pcap = dpkt.pcap.Reader(file_name)

#     for ts, buf in pcap:
#         eth = dpkt.ethernet.Ethernet(buf)
#         ip = eth.data
#         tcp = ip.data

#         sport = tcp.sport
#         dport = tcp.dport

#         # for i, tcp_flow in enumerate(tcp_flows):

# Getting # of Triple Acks and Timeouts
def retransmissions(file_name, tcp_flows):
    # result
    triple_dup = 0
    timeout = 0
    result = []
    tcp_packets = []

    file_name = open(file_name, "rb")
    for _, buf in dpkt.pcap.Reader(file_name):
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        tcp_packets.append(tcp) # allocating tcp of each packet

    for tcp_flow in tcp_flows:
        from_sender = [] # packet from sender -> receiver
        from_receiver = [] # packet from receiver -> sender
        sender_port = tcp_flow[0]
        receiver_port = tcp_flow[2]
        handshake = 1
        
        for pkt in tcp_packets:
            if handshake < 4 and ((pkt.sport == sender_port and pkt.dport == receiver_port) or (pkt.sport == receiver_port and pkt.dport == sender_port)): # bypass three-way handshake
                handshake += 1
                continue
            if(pkt.sport == sender_port and pkt.dport == receiver_port):
                from_sender.append((pkt.seq, pkt.ack))
            elif(pkt.sport == receiver_port and pkt.dport == sender_port):
                from_receiver.append((pkt.seq, pkt.ack))
            
        sender_receiver_count = Counter([packet[0] for packet in from_sender])
        receiver_sender_count = Counter([packet[1] for packet in from_receiver])

        duplicate_seq_check = [seq for seq, count in sender_receiver_count.items() if count > 1]
        triple_dup_check = [ack for ack, count in receiver_sender_count.items() if count > 3]
        print(triple_dup_check)
        intersection = list(set(triple_dup_check) & set(duplicate_seq_check)) # intersection of the set of two arrays

        length_of_intersection = len(intersection) 
        length_of_trip_dup = len(duplicate_seq_check) 

        pkt_out_order = 0
        for each in intersection:
            first_dup = 0
            
            # From Receiver -> Sender
            count = 0 # reset
            for pkt in from_receiver:
                if pkt[1] == each:
                    count = count + 1
                if count == 2:
                    first_dup = pkt[0]
                    break

            # From Sender -> Receiver
            count = 0 
            for pkt in from_sender:
                if pkt[0] == each:
                    count = count + 1
                if count == 2:
                    if first_dup > pkt[0]: 
                        pkt_out_order += 1
                    break
 
        triple_dup = length_of_intersection - pkt_out_order
        timeout = length_of_trip_dup - triple_dup
        result.append((triple_dup, timeout))

    return result


if __name__=="__main__":
    file_name = sys.argv[1] # fileName argument when program is being ran (e.g. python analysis_pcap_tcp.py *assignment2.pcap*)
    flows = tcpFlows(file_name) # returns the number of flows in the pcap file (Part A.a)
    
    transaction_output, throughput_output = getTransactionsAndThroughput(file_name, flows) # Part A.b&c
    # congestionWindow(file_name, flows) 
    retransmissions_output = retransmissions(file_name, flows)
    print(retransmissions_output)
    # PRINTING STARTS
    print("-" * 100)

    print("|  TCP FLOW  |         TCP TUPLE (SRCPORT, SRCIP, DESTPORT, DESTIP)         |      THROUHGPUT      |")

    for index, flow in enumerate(flows, 1):
        print("-" * 100)
        print(f"|      {index}     |        {flows[index - 1]}        |  {throughput_output[index - 1]}  |")

    print("-" * 100, "\n\n")

    for index, tcp_flow in enumerate(flows, 1):
        print("\t\tFIRST TWO TRANSACTIONS AFTER CONNECTION SETUP FOR TCP FLOW", index)
        print("-" * 100)
        print("|           SOURCE -> DESTINATION          | (SEQ NUMBER, ACK NUMBER) |    RECEIVE WINDOWS SIZE   |")
        print("-" * 100)
        for i in range(2):
                print(transaction_output[(2 * (index - 1))][i]) # transaction from sender to receiver 
                print(transaction_output[(2 * (index - 1)) + 1][i]) # transaction from receiver to sender
                print("-" * 100)
        print("\n# of times retransmission occurred due to triple duplicate acknowledgments:", retransmissions_output[((index - 1))][0])
        print("# of times retransmission occurred due to timeouts:", retransmissions_output[((index - 1))][1])
        print("\n")


# CREDITS
# https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
# https://www.geeksforgeeks.org/python-counter-objects-elements/
# https://dpkt.readthedocs.io/en/latest/examples.html#jon-oberheide-s-examples
# https://www.howtouselinux.com/post/tcp-flags