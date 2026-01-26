from scapy.all import *
from scapy.layers.inet import IP, TCP, fragment

from wireshark_exercise_generator.exercises.utils import ensure_params
from wireshark_exercise_generator.exercises.utils.common_utils import make_ips_for_student, sid_to_seed, random_high_port, filename, \
    random_well_known_port, make_random_client_ip, make_random_server_ip
from wireshark_exercise_generator.exercises.utils.tcp_utils import tcp_segment

from wireshark_exercise_generator.exercises.utils.solutions import solutions


def simple_http_single_req_resp(client_ip,
                                server_ip,
                                client_port,
                                server_port,
                                mss=1200,
                                ip_frag=True,
                                ip_fragsize=1400,
                                start_time=0.0,
                                packet_tx_time_mean=0.01,
                                http_body_resp_size=1000,
                                savefile=False):
    """
    Exercise 2:
    - TCP 3-way handshake
    - HTTP-like GET
    - Large HTTP-like response segmented by MSS
    - Optional IP fragmentation of each TCP segment

    Params:
        student_id : per-student variation seed
        mss        : desired TCP Maximum Segment Size (bytes) for data
        ip_frag    : if True, also fragment each IP packet at IP layer
        ip_fragsize: IP data size per fragment (only used if ip_frag=True)
    """
    #client_ip, server_ip, _, _ = make_ips_for_student(student_id)

    # Seed RNG so each student has stable HTTP size & ports
    exercise_id  = str(uuid.uuid4())    # used for solutions

    ###### SOLUTIONS ######
    solutions.write(exercise_id, "Protocol: HTTP")
    solutions.write(exercise_id, f"Client: {client_ip}:{client_port}")
    solutions.write(exercise_id, f"Server: {server_ip}:{server_port}")

    conn_params_solution_line = f"Connection params:\n" \
                                f"\tMSS: {mss}\n" \
                                f"\tIP Fragment size: {ip_fragsize if ip_fragsize < mss else "No IP fragmentation required (mss < MTU)"}"
    solutions.write(exercise_id, conn_params_solution_line)
    #######################


    student_id = random.randint(1, 1_000_000)

    delta_time_func = lambda: round( random.expovariate(1/packet_tx_time_mean) ,3)
    cur_time = start_time

    client_port = client_port #random_high_port()
    server_port = server_port  # fixed for teaching

    pkts = []

    # Initial TCP SEQs
    isn_client = random.randint(1000, 5000)
    isn_server = random.randint(6000, 9000)

    # -----------------------------
    # TCP 3-way handshake
    # -----------------------------
    syn = IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="S", seq=isn_client
    )
    syn.time = cur_time
    cur_time += delta_time_func()
    syn_ack = IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port, dport=client_port, flags="SA", seq=isn_server, ack=isn_client + 1
    )
    syn_ack.time =cur_time
    cur_time += delta_time_func()
    ack = IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="A", seq=isn_client + 1, ack=isn_server + 1
    )
    ack.time = cur_time
    cur_time += delta_time_func()

    pkts += [syn, syn_ack, ack]

    # -----------------------------
    # HTTP-like GET with SID
    # -----------------------------
    path = f"/index_sid{student_id}.html"
    host = f"sid{student_id}.lab-http.example"
    http_get_payload = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: SID/{student_id}\r\n"
        "\r\n"
    ).encode()
    len_get = len(http_get_payload)

    psh_ack = IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port,
        dport=server_port,
        flags="PA",
        seq=ack.seq,         # client seq after handshake
        ack=ack.ack          # acking server ISN+1
    ) / Raw(load=http_get_payload)
    psh_ack.time = cur_time
    cur_time += delta_time_func()

    pkts.append(psh_ack)

    # -----------------------------
    # Large HTTP response body
    # -----------------------------
    # Body size per student (KB): deterministic but varied
    #body_size_kb = random.choice([5, 50, 200])   # 5 KB, 50 KB, 200 KB
    body_size = http_body_resp_size #body_size_kb * 1024              # bytes

    pattern = (f"B".encode()) * http_body_resp_size
    body = pattern[:body_size]

    solutions.write(exercise_id, f"Server response body size: {body_size} Bytes")

    headers = (
        "HTTP/1.1 200 OK\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Content-Type: text/plain\r\n"
        f"X-SID-Payload-Size: {len(body)}\r\n"
        "\r\n"
    ).encode()

    http_resp_payload = headers + body

    # -----------------------------
    # TCP segmentation with MSS
    # -----------------------------
    # Server starts sending at seq = ack.ack (server ISN+1)
    # and acks the GET: ack = client seq after GET
    segments = tcp_segment(
        ip_src=server_ip,
        ip_dst=client_ip,
        sport=server_port,
        dport=client_port,
        seq_start=ack.ack,            # server seq start
        ack_num=ack.seq + len_get,    # ack of GET bytes
        payload=http_resp_payload,
        mss=mss
    )
    # add time to each segment



    if not segments:
        # Shouldn't happen unless http_resp_payload is empty
        server_last_seq = ack.ack
    else:
        if ip_frag:
            # IP fragmentation per TCP segment
            final_segs = []
            for i, seg in enumerate(segments):
                frags = fragment(seg, fragsize=ip_fragsize)
                for frag in frags:
                    frag[IP].id = i
                    frag.time = cur_time
                    cur_time += delta_time_func()
                final_segs.extend(frags)
            pkts.extend(final_segs)

            # Last TCP seq is taken from last *original* segment
            server_last_seq = segments[-1][TCP].seq + len(segments[-1][Raw].load)
        else:
            # No IP fragmentation, just MSS-sized segments
            for seg in segments:
                seg.time = cur_time
                cur_time += delta_time_func()
            pkts.extend(segments)
            server_last_seq = segments[-1][TCP].seq + len(segments[-1][Raw].load)

    # -----------------------------
    # FIN / teardown
    # -----------------------------
    fin = IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port,
        dport=server_port,
        flags="FA",
        seq=psh_ack.seq + len_get,    # client seq after GET
        ack=server_last_seq           # ack all response bytes
    )
    fin.time = cur_time
    cur_time += delta_time_func()

    fin_ack = IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port,
        dport=client_port,
        flags="FA",
        seq=server_last_seq,          # server seq after data
        ack=fin.seq + 1               # ack client's FIN
    )
    fin_ack.time = cur_time
    cur_time += delta_time_func()

    last_ack = IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port,
        dport=server_port,
        flags="A",
        seq=fin.seq + 1,
        ack=fin_ack.seq + 1
    )
    last_ack.time = cur_time
    cur_time += delta_time_func()

    pkts += [fin, fin_ack, last_ack]

    if savefile:
        wrpcap(filename("simple_http_single_req_resp", student_id), pkts)

    return pkts


@ensure_params(param_name='flow_parameters',
               required=['mss','ip_fragsize','http_body_resp_size',
                         'client_ip', 'server_ip',
                         'client_port', 'server_port'],
               generators={
                   'http_body_resp_size': lambda: random.randint(1000, 10_000),
                   'client_port': random_high_port,
                   'server_port': random_well_known_port,
                   'client_ip': make_random_client_ip,
                   'server_ip': make_random_server_ip,
               },
               inplace=True)
def http_flow_generator(flow_parameters):
    return simple_http_single_req_resp(**flow_parameters)