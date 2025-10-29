# utils.py
from scapy.all import *
import time

def packet_to_dict(pkt):
    """Extract useful fields from a Scapy packet as a dict."""
    ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkt.time)) if hasattr(pkt, 'time') else ''
    src = pkt[IP].src if IP in pkt else (pkt.src if hasattr(pkt, 'src') else '')
    dst = pkt[IP].dst if IP in pkt else (pkt.dst if hasattr(pkt, 'dst') else '')
    proto = pkt.lastlayer().name
    length = len(pkt)
    sport = dport = ''
    # try TCP/UDP ports
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        proto = 'TCP'
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        proto = 'UDP'
    elif ICMP in pkt:
        proto = 'ICMP'
    # fallback summary
    summary = pkt.summary()
    return {
        'time': ts,
        'src': src,
        'dst': dst,
        'sport': sport,
        'dport': dport,
        'proto': proto,
        'length': length,
        'summary': summary
    }

def sniff_packets(count=50, timeout=10, lfilter=None, iface=None):
    """Sniff packets and return list of dicts using packet_to_dict"""
    pkts = sniff(count=count, timeout=timeout, filter=None if lfilter is None else lfilter, iface=iface)
    return [packet_to_dict(p) for p in pkts]
