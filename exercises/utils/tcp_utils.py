import random

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









def build_tcp_handshake_near_first_data(
    client_ip,
    server_ip,
    client_port,
    server_port,
    first_data_time,
    isn_client=None,
    isn_server=None,
    syn_offset=0.003,
    synack_offset=0.002,
    ack_offset=0.001,
    rng_seed=None,
    client_initial_window=8192,
    server_initial_window=8192,
):
    """
    Build a standard 3-way handshake (SYN, SYN-ACK, ACK) scheduled
    just before the first data packet time.

    Returns:
        pkts          : [syn, syn_ack, ack]
        seq_client    : client seq after handshake
        seq_server    : server seq after handshake
    """

    if rng_seed is not None:
        random.seed(rng_seed)

    if isn_client is None:
        isn_client = random.randint(1000, 5000)
    if isn_server is None:
        isn_server = random.randint(6000, 9000)

    t_syn    = first_data_time - syn_offset
    t_synack = first_data_time - synack_offset
    t_ack    = first_data_time - ack_offset

    syn = IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port,
        dport=server_port,
        flags="S",
        window=client_initial_window,
        seq=isn_client,
    )
    syn.time = t_syn

    syn_ack = IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port,
        dport=client_port,
        flags="SA",
        seq=isn_server,
        ack=isn_client + 1,
        window=server_initial_window,
    )
    syn_ack.time = t_synack

    ack = IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port,
        dport=server_port,
        flags="A",
        seq=isn_client + 1,
        ack=isn_server + 1,
        window=client_initial_window,
    )
    ack.time = t_ack

    # Successful handshake:
    seq_client = isn_client + 1
    seq_server = isn_server + 1

    return [syn, syn_ack, ack], seq_client, seq_server





def build_tcp_teardown(
    client_ip,
    server_ip,
    client_port,
    server_port,
    client_seq,
    server_seq,
    client_ack,
    server_ack,
    last_event_time,
    initiator="client",     # "client" or "server"
    fin_offset=0.001,
    finack_offset=0.002,
    lastack_offset=0.003,
):
    """
    Build a 3-step TCP connection teardown with FIN/ACK and FIN/ACK:

      If initiator == "client":
        1) client -> server: FIN, ACK
        2) server -> client: FIN, ACK  (in same packet)
        3) client -> server: ACK

      If initiator == "server": symmetric.

    Parameters (all sequence/ack numbers are *pre-close* values):

      client_seq : sequence number the client will use for its FIN
      server_seq : sequence number the server will use for its FIN
      client_ack : ACK value the client currently sends (next expected from server)
      server_ack : ACK value the server currently sends (next expected from client)
      last_event_time : time of the last “normal” event (data/ACK) in the flow

    FIN consumes 1 sequence number, so the opposite side’s ACK increases by +1.

    Returns:
        [fin_pkt, fin_ack_pkt, last_ack_pkt]
    """

    t_fin    = last_event_time + fin_offset
    t_finack = last_event_time + finack_offset
    t_last   = last_event_time + lastack_offset

    if initiator == "client":
        # 1) Client -> Server: FIN, ACK
        fin = IP(src=client_ip, dst=server_ip) / TCP(
            sport=client_port,
            dport=server_port,
            flags="FA",
            seq=client_seq,
            ack=client_ack,
        )
        fin.time = t_fin

        # 2) Server -> Client: FIN, ACK (acks client's FIN)
        fin_ack = IP(src=server_ip, dst=client_ip) / TCP(
            sport=server_port,
            dport=client_port,
            flags="FA",
            seq=server_seq,
            ack=server_ack + 1,   # ACK client's FIN (1 byte)
        )
        fin_ack.time = t_finack

        # 3) Client -> Server: final ACK (acks server's FIN)
        last_ack = IP(src=client_ip, dst=server_ip) / TCP(
            sport=client_port,
            dport=server_port,
            flags="A",
            seq=client_seq + 1,   # client consumed its FIN
            ack=server_seq + 1,   # ACK server's FIN
        )
        last_ack.time = t_last

    elif initiator == "server":
        # 1) Server -> Client: FIN, ACK
        fin = IP(src=server_ip, dst=client_ip) / TCP(
            sport=server_port,
            dport=client_port,
            flags="FA",
            seq=server_seq,
            ack=server_ack,
        )
        fin.time = t_fin

        # 2) Client -> Server: FIN, ACK (acks server's FIN)
        fin_ack = IP(src=client_ip, dst=server_ip) / TCP(
            sport=client_port,
            dport=server_port,
            flags="FA",
            seq=client_seq,
            ack=client_ack + 1,   # ACK server's FIN
        )
        fin_ack.time = t_finack

        # 3) Server -> Client: final ACK (acks client’s FIN)
        last_ack = IP(src=server_ip, dst=client_ip) / TCP(
            sport=server_port,
            dport=client_port,
            flags="A",
            seq=server_seq + 1,
            ack=client_seq + 1,
        )
        last_ack.time = t_last

    else:
        raise ValueError("initiator must be 'client' or 'server'")

    return [fin, fin_ack, last_ack]


