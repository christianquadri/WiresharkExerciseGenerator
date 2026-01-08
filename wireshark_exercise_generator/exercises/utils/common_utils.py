import hashlib
import random
import os

from scapy.packet import Raw
from scapy.layers.inet import fragment, IP, TCP


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def sid_to_seed(student_id):
    """
    Turn any student_id (int or string) into a reproducible integer seed.
    """
    s = str(student_id)
    h = hashlib.sha256(s.encode()).hexdigest()
    # Take first 8 hex digits -> int
    return int(h[:8], 16)


def random_high_port():
    # typical ephemeral port range
    return random.randint(10000, 60000)

def random_port():
    # typical ephemeral port range
    return random.randint(1000, 40000)


def random_well_known_port():
    return random.choice([80, 443, 8080, 8443])

def make_random_client_ip():
    x = random.randint(1, 254)
    y = random.randint(1, 254)

    client_ip = f"192.{x}.{y}.100"
    return client_ip

def make_random_server_ip():
    x = random.randint(1, 254)
    y = random.randint(1, 254)
    server_ip = f"10.{x}.{y}.200"
    return server_ip


def make_ips_for_student(student_id):
    """
    Derive some deterministic private IPs from the student ID.
    """
    seed = sid_to_seed(student_id)
    random.seed(seed)

    # First octet fixed, others derived (but still in private ranges)
    # Example networks: 10.X.Y.Z and 192.168.X.Y
    x = random.randint(1, 254)
    y = random.randint(1, 254)
    z = random.randint(1, 254)

    client_ip = f"192.{x}.{y}.100"
    server_ip = f"10.{x}.{y}.200"
    gateway_ip = f"192.168.{x}.1"
    local_dns_ip = f"192.168.{x}.53"

    return client_ip, server_ip, gateway_ip, local_dns_ip


def make_dns_name_for_student(student_id):
    """
    Make a deterministic but unique-looking DNS name per student.
    """
    s = str(student_id)
    # simple sanitized label
    label = "".join(ch for ch in s if ch.isalnum()).lower() or "student"
    return f"www.{label}.lab-example.com."


def filename(prefix, student_id=None):
    if student_id:
        prefix = f"{prefix}_{student_id}"
    return os.path.join('pcap_output',f"{prefix}.pcap")





def exponential_times(n_packets, rate, start_time=0.0):
    """
    Generate monotonically increasing timestamps for n_packets using
    exponential inter-arrival times.

    rate: λ (packets per second). Mean inter-arrival = 1 / rate.
    start_time: first packet time offset (seconds, relative to some origin).
    """
    times = []
    t = start_time
    for _ in range(n_packets):
        dt = 0.001 + random.expovariate(rate)   # mean 1/rate
        t += round(dt,3)
        times.append(t)
    return times

