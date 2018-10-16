from scapy.all import *

amount_of_packets = 50

capture = sniff(count=amount_of_packets)

print(type(capture))
print(len(capture))
print(capture)

