#!/usr/bin/env python3
import os
import pprint

import yaml

from scapy.all import *
import random
import string
import hashlib
import json

from scapy.layers.dns import DNSQR, DNSRR, DNS
from scapy.layers.inet import IP, UDP, ICMP, TCP
from scapy.layers.l2 import Ether, ARP

from exercises import flow_generator

from exercises.utils.common_utils import filename, sid_to_seed, make_ips_for_student, random_high_port, \
    make_dns_name_for_student







if __name__ == "__main__":
    # Example usage:
    # - single student:
    #   generate_all_pcaps_for_student(42)
    #
    # - multiple:
    #   for sid in range(1, 31): generate_all_pcaps_for_student(sid)

    # Create the pcap_output directory if it doesn't exist yet:
    os.makedirs('pcap_output', exist_ok=True)

    with open('exercise_specification.yaml') as f:
        configurations = yaml.safe_load(f)

    #set seed
    random.seed(configurations['seed'])
    # generate flows from templates
    all_packets = []
    for flow_id, flow_conf in enumerate(configurations['flow_list']):
        packets = flow_generator(flow_id, flow_conf['flow_template'])
        all_packets.extend(packets)

    # sort packets by time
    all_packets.sort(key=lambda p: getattr(p, "time", 0.0))
    wrpcap('pcap_output/exercise.pcap', all_packets)


