from scapy.all import *

amount_of_packets = 50

capture = sniff(count=amount_of_packets)

print(type(capture))
print(len(capture))
print(capture)

count = 1
# Loops through pcap lines
while count:

    ethernet_frame = capture[0]
    ip_packet = ethernet_frame.payload
    segment = ip_packet.payload
    data = segment.payload

    print("Packet #: ", count)
    print(ethernet_frame.summary())
    print(ip_packet.summary())
    print(segment.summary())
    print(data.summary())

    count += 1
