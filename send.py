#!/usr/bin/env python3
"""Send one UDP packet, optionally inside the custom tunnel header.

    python3 send.py <ip address> "<message>"                        plain IPv4
    python3 send.py <ip address> "<message>" --tunnel N             tunnelled to exit N
    python3 send.py <ip address> "<message>" --tunnel N --hops H    ... with hop limit H
"""
import argparse

from scapy.all import IP, UDP, ByteField, Ether, Packet, ShortField, bind_layers, get_if_hwaddr, get_if_list, sendp

DEFAULT_HOPS = 8  # the lab path h1 -> s1 -> s2 -> h2/h3 crosses 2 switches; 8 leaves room to grow


class MyTunnel(Packet):
    name = "MyTunnel"
    fields_desc = [
        ShortField("proto_id", 0x0800),
        ShortField("dst_id", 0),
        ByteField("hop_limit", DEFAULT_HOPS),
    ]


bind_layers(Ether, MyTunnel, type=0x1212)
bind_layers(MyTunnel, IP, proto_id=0x0800)


def hop_limit(value):
    hops = int(value)
    if not 0 <= hops <= 255:
        raise argparse.ArgumentTypeError("the hop limit is 8 bits: 0 to 255")
    return hops


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ip")
    ap.add_argument("message")
    ap.add_argument("--tunnel", type=int, metavar="N", help="tunnel exit to deliver to")
    ap.add_argument("--hops", type=hop_limit, default=DEFAULT_HOPS, metavar="H",
                    help=f"tunnel hop limit: how many switches the packet may cross (default {DEFAULT_HOPS})")
    args = ap.parse_args()

    iface = next(i for i in get_if_list() if i.endswith("-eth0"))
    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff")
    if args.tunnel is not None:
        pkt = pkt / MyTunnel(dst_id=args.tunnel, hop_limit=args.hops)
    pkt = pkt / IP(dst=args.ip) / UDP(sport=4321, dport=4321) / args.message
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)
    print(f"Sent from {iface}.")


if __name__ == "__main__":
    main()
