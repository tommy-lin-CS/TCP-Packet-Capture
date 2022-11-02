# CSE 310 Programming Assignment #2
## How to run this program?
1. Open Terminal on your computer.
1. Navigate to the directory that the file, analysis_pcap_tcp.py, is located.
1. Make sure that the .pcap that you wish to run is also in the directory.
1. Type *python analysis_pcap_tcp.py <.pcap file>* and press enter.
    1. In our assignment, we will be running python analysis_pcap_tcp.py assignment2.pcap

**Please make sure you have Python and dpkt library installed on your computer before attempting to run the steps above. You may find the follow instructions to install python and dpkt here:**
* https://www.python.org/downloads/
* https://dpkt.readthedocs.io/en/latest/installation.html


## Output (assignment2.pcap)
```
----------------------------------------------------------------------------------------------------
|  TCP FLOW  |         TCP TUPLE (SRCPORT, SRCIP, DESTPORT, DESTIP)         |      THROUHGPUT      |
----------------------------------------------------------------------------------------------------
|      1     |        (43498, '130.245.145.12', 80, '128.208.2.198')        |  5342630.8964322135  |
----------------------------------------------------------------------------------------------------
|      2     |        (43500, '130.245.145.12', 80, '128.208.2.198')        |  1268045.245854818  |
----------------------------------------------------------------------------------------------------
|      3     |        (43502, '130.245.145.12', 80, '128.208.2.198')        |  1626650.4791975326  |
---------------------------------------------------------------------------------------------------- 




		FIRST TWO TRANSACTIONS AFTER CONNECTION SETUP FOR TCP FLOW 1
----------------------------------------------------------------------------------------------------
|           SOURCE -> DESTINATION          | (SEQ NUMBER, ACK NUMBER) |    RECEIVE WINDOWS SIZE   |
----------------------------------------------------------------------------------------------------
| 130.245.145.12:43498 -> 128.208.2.198:80 | (705669103, 1921750144) |             3             |
| 128.208.2.198:80 -> 130.245.145.12:43498 | (1921750144, 705669127) |             3             |
----------------------------------------------------------------------------------------------------
| 130.245.145.12:43498 -> 128.208.2.198:80 | (705669127, 1921750144) |             3             |
| 128.208.2.198:80 -> 130.245.145.12:43498 | (1921750144, 705670575) |             3             |
----------------------------------------------------------------------------------------------------
------------------------------------------------------------
|TRIPLE DUPLICATE ACKS| TIMEOUTS |    FIRST 3 CWND SIZE   |
------------------------------------------------------------
|          2          |    1     |       14, 18, 41       |
------------------------------------------------------------



		FIRST TWO TRANSACTIONS AFTER CONNECTION SETUP FOR TCP FLOW 2
----------------------------------------------------------------------------------------------------
|           SOURCE -> DESTINATION          | (SEQ NUMBER, ACK NUMBER) |    RECEIVE WINDOWS SIZE   |
----------------------------------------------------------------------------------------------------
| 130.245.145.12:43500 -> 128.208.2.198:80 | (3636173852, 2335809728) |             3             |
| 128.208.2.198:80 -> 130.245.145.12:43500 | (2335809728, 3636173876) |             3             |
----------------------------------------------------------------------------------------------------
| 130.245.145.12:43500 -> 128.208.2.198:80 | (3636173876, 2335809728) |             3             |
| 128.208.2.198:80 -> 130.245.145.12:43500 | (2335809728, 3636175324) |             3             |
----------------------------------------------------------------------------------------------------
------------------------------------------------------------
|TRIPLE DUPLICATE ACKS| TIMEOUTS |    FIRST 3 CWND SIZE   |
------------------------------------------------------------
|          4          |    90    |       10, 20, 33       |
------------------------------------------------------------



		FIRST TWO TRANSACTIONS AFTER CONNECTION SETUP FOR TCP FLOW 3
----------------------------------------------------------------------------------------------------
|           SOURCE -> DESTINATION          | (SEQ NUMBER, ACK NUMBER) |    RECEIVE WINDOWS SIZE   |
----------------------------------------------------------------------------------------------------
| 130.245.145.12:43502 -> 128.208.2.198:80 | (2558634630, 3429921723) |             3             |
| 128.208.2.198:80 -> 130.245.145.12:43502 | (3429921723, 2558634654) |             3             |
----------------------------------------------------------------------------------------------------
| 130.245.145.12:43502 -> 128.208.2.198:80 | (2558634654, 3429921723) |             3             |
| 128.208.2.198:80 -> 130.245.145.12:43502 | (3429921723, 2558636102) |             3             |
----------------------------------------------------------------------------------------------------
------------------------------------------------------------
|TRIPLE DUPLICATE ACKS| TIMEOUTS |    FIRST 3 CWND SIZE   |
------------------------------------------------------------
|          0          |    0     |       20, 43, 44       |
------------------------------------------------------------
```



## Explanation
### Part A
a. The code loops through the entire TCP file. Starting from the SYN flag, if the source port, source IP address, destination port, and destination IP address has already been recorded, we do not record it again. If not, we append it to our TCP Flow tuple. The TCP Flow tuple should include the (source port, source IP address, destination port, destination IP address) by format.

b. To get the first two transactions of the flow, I used the TCP Flow tuple I found in Part A.a. Basically, I look through the list for each TCP Flow, and I get the first and second transactions sent from sender to receiver and from receiver to sender. I record each of their sequence number -> acknowledgment number and their receive window size.

c. To get the throughput of each TCP Flow, I add the length (data) of each TCP packet in that flow. In addition, I would also check for SYN_FLAG and mark the timestamp of it and check for FIN_FLAG and mark the timestamp of it. After that, to get the period, I take the timestamp of the FIN_FLAG subtract the timestamp of the SYN_FLAG. Then I calculate the throughput for that flow by dividing the computed length (data) of each TCP packet by the period.

### Part B
a. To get the first three congestion windows, I first calculated the RTT for each flow. To calculate the RTT for each flow, I subtracted the last timestamp of the handshake by the first timestamp of the handshake. Then, I counted how many valid packets are between first TCP packet timestamp (min_ts) in that flow to the first TCP packet timestamp + my estimated RTT (max_ts). To get the next congestion window, I set the min_ts to my last max_ts and set the max_ts to my new min_ts + my estimated RTT. 
The rate that congestion window grows is due to TCP slow start. The congestion window doubles per RTT until it hits the slow start threshold then it will start increasingly linearly. This can be shown in our third flow which the congestion window changes from 20 -> 43 -> 44 (doubles, then linear).

b. To get the triple duplicate acknowledgments and timeouts, I first loop through each TCP Flow to get the sequence numbers and acknowledgment numbers of each packet in each flow after the three-way handshake. Then I use the Python Counter which is part of the Collections to count the number of times a sequence number (saved it to duplicate_seq_check) or acknowledgment number (saved it to triple_dup_ack) appears from the sender to receiver and vice versa. Then I found the intersection (the alikes) of both of the array and saved it to a variable, intersection. Then I loop through each element in the intersection and check if there are packets where the first duplicate acknowledgment is after the retransmited packet count and I save that occurrance to a variable, pkt_out_order. Finally, to the number of triple duplicate acknowledgment, I take the length of the intersection subtract the pkt_out_order. To get the number of timeouts, I take the length of the triple duplicate knowledgments (when the number of acknowledgments is greater than 3) subtract the number of triple duplicate acknowledgments.

## Credits
https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
https://www.geeksforgeeks.org/python-counter-objects-elements/
https://dpkt.readthedocs.io/en/latest/examples.html#jon-oberheide-s-examples
https://www.howtouselinux.com/post/tcp-flags