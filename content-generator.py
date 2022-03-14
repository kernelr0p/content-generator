from scapy.all import *
import argparse
import time
import progressbar

def main(args):
    
    src_ip=args.src_ip
    dst_ip=args.dst_ip
    content=args.content
    iface=args.iface
    flags_tcp=args.flags.upper()
    stateful=args.stateful
    number_of_packets=args.number
    sport = random.randint(1024,65535)
    dport=int(args.dport)
    ether=Ether(src=get_if_hwaddr(iface))
    i=IP(src=src_ip,dst=dst_ip)
    #tcp=TCP(sport=sport, dport=dport, flags=flags)
    #pkt = ether/i/tcp/content
    pbar = progressbar.ProgressBar()
    pbar.start()
    content = "GET /etc/passwd HTTP/1.0\r\nHOST: 192.168.210.141\r\n\r\n"
    if stateful:
        SYN=TCP(sport=sport,dport=dport,flags='S',seq=1000)
        SYNACK=sr1(i/SYN)
        ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
        send(i/ACK)
        CUSTOM=TCP(sport=sport, dport=dport, flags=flags_tcp,seq=SYNACK.ack, ack=SYNACK.seq + 1)
        reply,error = sr(i/fuzz(CUSTOM)/content,multi=1,timeout=1)
        for r in reply:
            r[0].show2()
            r[1].show2()
    else:
        mysocket=socket.socket()
        mysocket.connect((dst_ip,dport))
        mystream=StreamSocket(mysocket)
        CUSTOM=TCP(sport=sport, dport=dport, flags=flags_tcp)
        ascapypacket=i/fuzz(TCP())/content
        mystream.send(ascapypacket)
    pbar.finish()

def parseArgs():
    usage = "Usage: python content-generator.py [-v] -c content -n number_of_packets -s SRC_IP -d DST_IP -i interface -w pcap -f flags --stateful --teardown"
    parser = argparse.ArgumentParser(description=usage)

    parser.add_argument("--stateful", help="Perform 3-way handshake",dest="stateful")
    parser.add_argument("--teardown", help="Connection teardown",dest="teardown")
    parser.add_argument("-c","--content", help="Content to add",dest="content")
    parser.add_argument("-n","--number", help="Number of packets",type=int,dest="number")
    parser.add_argument("-s","--src", help="Source IP Address",dest="src_ip")
    parser.add_argument("-d","--dst", help="Destination IP Address",dest="dst_ip")
    parser.add_argument("-i","--iface", help="Interface to use",dest="iface")	
    parser.add_argument("-dp","--dport", help="Destination port",dest="dport")	
    parser.add_argument("-f","--flags", help="Flags",dest="flags")	
    parser.add_argument("-w","--wpcap", help="Name of pcap file")
    parser.add_argument("-v","--verbose", help="Verbose hex output of raw alert")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    main(args)

if __name__ == "__main__":
    parseArgs()
