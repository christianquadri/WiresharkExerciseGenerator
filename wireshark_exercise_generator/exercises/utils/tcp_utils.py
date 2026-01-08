from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


def tcp_segment(ip_src, ip_dst, sport, dport, seq_start, ack_num, payload, mss=1460, start_time = 0.0):
    """
    Splits a payload into multiple TCP segments with correct SEQ numbers.
    Returns a list of IP/TCP/Raw packets (no IP fragmentation).
    """
    segments = []
    seq = seq_start

    for i in range(0, len(payload), mss):
        chunk = payload[i:i + mss]

        seg = (
            IP(src=ip_src, dst=ip_dst) /
            TCP(
                sport=sport,
                dport=dport,
                flags="PA",    # push + ack; typical data packet
                seq=seq,
                ack=ack_num
            ) /
            Raw(load=chunk)
        )
        seg.time = start_time + i * 0.001

        segments.append(seg)
        seq += len(chunk)

    return segments


