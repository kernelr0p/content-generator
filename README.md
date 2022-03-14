# Content Generator
Tool to generate a number of TCP packets with custom content. Useful to test IDS/IPS rules.

    Usage: python content-generator.py [-v] -c content -n number_of_packets -s SRC IP -d DST IP 
    -i interface -w pcap [-A]
    
    -v verbose,               print verbose output
    -c content,               add custom content to the TCP payload
    -n number_of_packets,     number of packets to send to
    -s SRC IP,                source IP Address
    -d DST IP,                destination IP Address
    -i inteface,              interface to use
    -w pcap,                  ".pcap" output file
    -A,                       add a TCP ACK packet
