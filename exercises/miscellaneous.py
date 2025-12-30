import random

from scapy.layers.dns import DNSQR, DNSRR, DNS
from scapy.layers.inet import IP, UDP, ICMP, TCP
from scapy.layers.l2 import Ether, ARP
from scapy.all import *

from exercises.utils.common_utils import filename, sid_to_seed, make_ips_for_student, random_high_port, \
    make_dns_name_for_student

# ------------------------------------------------------------
# Exercise 1 – ICMP ping
# ------------------------------------------------------------

def make_ex1_icmp_ping(student_id):
    client_ip, server_ip, _, _ = make_ips_for_student(student_id)

    pkts = []

    # Use seed so sequence numbers & payloads are stable per student
    random.seed(sid_to_seed(student_id) + 1)

    # A little variety in how many pings:
    count = random.randint(3, 7)

    for i in range(1, count + 1):
        payload_req = f"SID{student_id}_ping{i}".encode()
        payload_rep = f"SID{student_id}_pong{i}".encode()

        req = IP(src=client_ip, dst=server_ip) / ICMP(id=0x1234, seq=i) / Raw(load=payload_req)
        rep = IP(src=server_ip, dst=client_ip) / ICMP(type="echo-reply", id=0x1234, seq=i) / Raw(load=payload_rep)
        pkts.extend([req, rep])

    wrpcap(filename("ex1_icmp_ping", student_id), pkts)


# ------------------------------------------------------------
# Exercise 3 – DNS query/response
# ------------------------------------------------------------

def make_ex3_dns_query_response(student_id):
    _, _, _, dns_server_ip = make_ips_for_student(student_id)
    client_ip = f"192.0.2.{(sid_to_seed(student_id) % 200) + 10}"  # documentation net

    random.seed(sid_to_seed(student_id) + 3)

    qname = make_dns_name_for_student(student_id)

    # Use slightly randomized source port
    sport = random_high_port()

    dns_query = IP(src=client_ip, dst=dns_server_ip) / UDP(sport=sport, dport=53) / DNS(
        id=random.randint(1, 0xFFFF),
        rd=1,
        qd=DNSQR(qname=qname, qtype="A", qclass="IN")
    )

    # Answer with a deterministic but different IP per student
    a_octet_3 = (sid_to_seed(student_id) % 250) or 1
    a_octet_4 = (sid_to_seed(student_id) % 200) + 10
    answer_ip = f"203.0.113.{a_octet_4}"  # another documentation net

    dns_response = IP(src=dns_server_ip, dst=client_ip) / UDP(sport=53, dport=sport) / DNS(
        id=dns_query[DNS].id,
        qr=1,
        aa=1,
        rd=1,
        ra=1,
        qd=DNSQR(qname=qname, qtype="A", qclass="IN"),
        an=DNSRR(rrname=qname, type="A", rclass="IN", ttl=300, rdata=answer_ip)
    )

    pkts = [dns_query, dns_response]
    wrpcap(filename("ex3_dns_query_response", student_id), pkts)


# ------------------------------------------------------------
# Exercise 4 – ARP basic + gratuitous
# ------------------------------------------------------------

def make_ex4_arp_basic(student_id):
    client_ip, server_ip, gateway_ip, _ = make_ips_for_student(student_id)

    random.seed(sid_to_seed(student_id) + 4)

    # Generate deterministic MACs
    def rand_mac(prefix="02"):
        # locally administered unicast MACs
        rest = [random.randint(0x00, 0xFF) for _ in range(5)]
        return ":".join([prefix] + [f"{b:02x}" for b in rest])

    client_mac = rand_mac("02")
    server_mac = rand_mac("06")

    pkts = []

    # ARP request: who has gateway_ip?
    arp_req = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc=client_mac,
        psrc=client_ip,
        hwdst="00:00:00:00:00:00",
        pdst=gateway_ip
    )

    # ARP reply: gateway_ip is at server_mac
    arp_rep = Ether(src=server_mac, dst=client_mac) / ARP(
        op=2,
        hwsrc=server_mac,
        psrc=gateway_ip,
        hwdst=client_mac,
        pdst=client_ip
    )

    # Gratuitous ARP from "server" for its own IP (server_ip)
    grat_arp = Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        hwsrc=server_mac,
        psrc=server_ip,
        hwdst="00:00:00:00:00:00",
        pdst=server_ip
    )

    pkts.extend([arp_req, arp_rep, grat_arp])
    wrpcap(filename("ex4_arp_basic", student_id), pkts)