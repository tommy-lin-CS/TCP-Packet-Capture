from collections import Counter
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
        
        syn_flag = ( tcp.flags & 0x02 ) != 0

        sport = tcp.sport # TCP Source Port #
        dport = tcp.dport # TCP Destination Port #

        if syn_flag: 
            existBool = False # boolean used to check if flow already been recorded
            
            # check for tcp flows in the tuple already
            for tcp_flow in tcp_flows: 
                if (sport == tcp_flow[0] or sport == tcp_flow[2]):
                    if (dport == tcp_flow[0] or dport == tcp_flow[2]):
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

    first_two_transactions = [[] for x in range((length_of_tcp_flows) * 2)]
       
    temp = [-1] * (length_of_tcp_flows) # temp used to store length tcp info of flows used to get throughput and period
    first = [-1] * (length_of_tcp_flows) # the first pkt timestamp for each tcp flow
    last = [-1] * (length_of_tcp_flows) # the last pkt timestamp for each tcp flow

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        fin_flag = ( tcp.flags & 0x01 ) != 0
        syn_flag = ( tcp.flags & 0x02 ) != 0
       
        sport = tcp.sport
        dport = tcp.dport

        # GET FIRST TWO TRANSACTIONS (Part A.b)
        for i, tcp_flow in enumerate(tcp_flows): 
            if ((tcp_flow[0] == sport and tcp_flow[2] == dport) or (tcp_flow[0] == dport and tcp_flow[2] == sport)) and flow_count_trans[i] < num_of_handshakes:
                flow_count_trans[i] += 1
            else:
                if tcp_flow[0] == sport and tcp_flow[2] == dport:
                    if len(first_two_transactions[2 * i]) == 0: 
                        first_two_transactions[2 * i].append(f'| {sender}:{sport} -> {receiver}:{dport} | ({tcp.seq}, {tcp.ack}) |             {tcp.win}             |')
                    elif len(first_two_transactions[2 * i]) == 1:
                        first_two_transactions[2 * i].append(f'| {sender}:{sport} -> {receiver}:{dport} | ({tcp.seq}, {tcp.ack}) |             {tcp.win}             |')
                elif tcp_flow[0] == dport and tcp_flow[2] == sport:
                    if len(first_two_transactions[(2 * i) + 1]) == 0:
                        first_two_transactions[(2 * i) + 1].append(f'| {receiver}:{sport} -> {sender}:{dport} | ({tcp.seq}, {tcp.ack}) |             {tcp.win}             |')
                    elif len(first_two_transactions[(2 * i) + 1]) == 1:
                        first_two_transactions[(2 * i) + 1].append(f'| {receiver}:{sport} -> {sender}:{dport} | ({tcp.seq}, {tcp.ack}) |             {tcp.win}             |')

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

# Getting Congestion Windows for each flow
def congestionWindow(file_name, tcp_flows):
    file_name = open(file_name, "rb")
    pcap = dpkt.pcap.Reader(file_name)

    rtt = [] # array that stores RTT
    handshakes = [[] for _ in range(len(tcp_flows))] # allocates space for the first three handshakes
    handshake_counter = [0 for _ in range(len(tcp_flows))] # counter for the number of handshakes up to 3
    tcp_packet = [[] for _ in range(len(tcp_flows))] # tcp flow packets

    # general stuff
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        sport = tcp.sport
        dport = tcp.dport

    # first, find the RTT
        for i, tcp_flow in enumerate(tcp_flows):
            if ((sport == tcp_flow[0] and dport == tcp_flow[2]) or (sport == tcp_flow[2] and dport == tcp_flow[0])): # on three-way handshake
                if(handshake_counter[i] < 3):
                    handshake_counter[i] = handshake_counter[i] + 1
                    handshakes[i].append(ts)
                tcp_packet[i].append((ts, tcp))
    
    # get cwnd time
    cwnd_result = []
    for j, flow in enumerate(tcp_flows):
        rtt.append(handshakes[j][2] - handshakes[j][0]) # append rtt
        min_ts = tcp_packet[j][3][0]
        max_ts = tcp_packet[j][3][0] + rtt[j]
        ceiling = tcp_packet[j][len(tcp_packet[j]) - 1][0]
        
        i = 0
        while i < 3:
            packet_counter = 0
            if max_ts <= ceiling:
                for pkt in tcp_packet[j]:
                    if min_ts <= pkt[0] < max_ts:
                        if pkt[1].sport == flow[0] and pkt[1].dport == flow[2]:
                            packet_counter = packet_counter + 1
                cwnd_result.append(packet_counter)
                min_ts = max_ts
                max_ts = max_ts + rtt[j]
            else: # max_ts > ceiling
                for pkt in tcp_packet[j]:
                    if min_ts <= pkt[0] <= ceiling:
                        if pkt[1].sport == flow[0] and pkt[1].dport == flow[2]:
                            packet_counter = packet_counter + 1
                cwnd_result.append(packet_counter)
                break
            i += 1
        # The congestion window grows due to TCP slow start. The congestion window doubles per RTT until 
        # it hits the slow start threshold then it will start increasingly linearly. This can be shown in our
        # third flow which the congestion window changes from 20 -> 43 -> 44 (doubles, then linear).

    return cwnd_result
        

# Getting # of Triple Acks and Timeouts
def retransmissions(file_name, tcp_flows):
    # result
    triple_dup = 0
    timeout = 0
    result = []
    tcp_packets = []

    file_name = open(file_name, "rb")
    pcap = dpkt.pcap.Reader(file_name)
    for _, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        tcp_packets.append(tcp) # allocating tcp packet

    for tcp_flow in tcp_flows:
        from_sender = [] # packet from sender -> receiver
        from_receiver = [] # packet from receiver -> sender
        sender_port = tcp_flow[0]
        receiver_port = tcp_flow[2]
        handshake = 0 # used to tell if handshake period has crossed
        index = 0
        for pkt in tcp_packets:
            if handshake < 3: # bypass three-way handshake
                if((pkt.sport == sender_port and pkt.dport == receiver_port) or (pkt.sport == receiver_port and pkt.dport == sender_port)):
                    handshake += 1
                    continue
            if(pkt.sport == sender_port and pkt.dport == receiver_port):
                from_sender.append((pkt.seq, pkt.ack, index))
                index = index + 1
            elif(pkt.sport == receiver_port and pkt.dport == sender_port):
                from_receiver.append((pkt.seq, pkt.ack, index))
                index = index + 1

        # Using Python Collections Library Counter to count the sequence and acknowledgment number occurrances
        sender_receiver_count = Counter([packet[0] for packet in from_sender])
        receiver_sender_count = Counter([packet[1] for packet in from_receiver])

        duplicate_seq_check = [seq for seq, count in sender_receiver_count.items() if count > 1] # filter out seq that appears more than 1
        triple_dup_check = [ack for ack, count in receiver_sender_count.items() if count > 3] # filter out ack that appears more than 3
        intersection = list(set(triple_dup_check) & set(duplicate_seq_check)) # intersection of the set of two arrays

        length_of_intersection = len(intersection) 
        length_of_trip_dup = len(duplicate_seq_check) 

        pkt_out_order = 0
        for each in intersection:
            first_dup = 0
            
            # From Receiver -> Sender
            count = 0 # count packet
            for pkt in from_receiver:
                if pkt[1] == each:
                    count = count + 1
                if count == 2:
                    first_dup = pkt[2] # setting the index of packet to the first duplicate we come across
                    break

            # From Sender -> Receiver
            count = 0 # count packet
            for pkt in from_sender:
                if pkt[0] == each:
                    count = count + 1 
                if count == 2:
                    if first_dup > pkt[2]: # check to see if the first duplicate (index of packet) we found earlier is greater than the index of the packet that sent from sender -> receiver
                        pkt_out_order += 1 # if so, increment this number to delete later
                    break
 
        triple_dup = length_of_intersection - pkt_out_order
        timeout = length_of_trip_dup - triple_dup
        result.append((triple_dup, timeout))

    return result

def main():
    flows = tcpFlows(file_name) # returns the number of flows in the pcap file (Part A.a)
    transaction_output, throughput_output = getTransactionsAndThroughput(file_name, flows) # Part A.b&c
    congestion_window_output = congestionWindow(file_name, flows) # Part B.a
    retransmissions_output = retransmissions(file_name, flows) # Part B.b

    # PRINTING STARTS
    print("-" * 100)

    print("|  TCP FLOW  |         TCP TUPLE (SRCPORT, SRCIP, DESTPORT, DESTIP)         |      THROUHGPUT      |")

    for index, flow in enumerate(flows, 1):
        print("-" * 100)
        print(f"|      {index}     |        {flows[index - 1]}        |  {throughput_output[index - 1]}  |")

    print("-" * 100, "\n")

    for index, tcp_flow in enumerate(flows, 1):
        print("\n\n\n\t\tFIRST TWO TRANSACTIONS AFTER CONNECTION SETUP FOR TCP FLOW", index)
        print("-" * 100)
        print("|           SOURCE -> DESTINATION          | (SEQ NUMBER, ACK NUMBER) |    RECEIVE WINDOWS SIZE   |")
        print("-" * 100)
        for i in range(2):
                print(transaction_output[(2 * (index - 1))][i]) # transaction from sender to receiver 
                print(transaction_output[(2 * (index - 1)) + 1][i]) # transaction from receiver to sender
                print("-" * 100)
        first_cwnd = congestion_window_output[(3 * (index - 1))] # transaction from sender to receiver 
        second_cwnd = congestion_window_output[(3 * (index - 1)) + 1] # transaction from receiver to sender
        third_cwnd = congestion_window_output[(3 * (index - 1)) + 2] # transaction from receiver to sender
        print("-" * 60)
        print("|TRIPLE DUPLICATE ACKS| TIMEOUTS |    FIRST 3 CWND SIZE   |")
        print("-" * 60)
        print(f"|          {retransmissions_output[((index - 1))][0]}          |    {retransmissions_output[((index - 1))][1]}    |       {first_cwnd}, {second_cwnd}, {third_cwnd}       |")
        print("-" * 60)

if __name__=="__main__":
    file_name = sys.argv[1] # fileName argument when program is being ran (e.g. python analysis_pcap_tcp.py *assignment2.pcap*)
    main() # main method call