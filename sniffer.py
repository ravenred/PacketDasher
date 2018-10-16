from scapy.all import *

amount_of_packets = 50

capture = sniff(count=amount_of_packets)

print(type(capture))
print(len(capture))
print(capture)

# Loops through pcap lines

for i in capture:

    ethernet_frame = capture[i]
    ip_packet = ethernet_frame.payload
    segment = ip_packet.payload
    data = segment.payload

    print("Packet #", i)
    print(ethernet_frame.summary())
    print(ip_packet.summary())
    print(segment.summary())
    print(data.summary())
    i += 1
