import logging
import random
import math
import struct
from typing import Iterable

import uuid

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from collections import deque
from dataclasses import dataclass

from wireshark_exercise_generator.exercises.utils import ensure_params
from wireshark_exercise_generator.exercises.utils.common_utils import random_high_port, make_random_client_ip, \
    make_random_server_ip, random_port

from wireshark_exercise_generator.exercises.utils.solutions import solutions

logger = logging.getLogger("TCPSIM")
logging.basicConfig(level=logging.INFO)
# ============================================================
#  Endpoint-level state: TX/RX FIFOs, ACK & SACK logic
# ============================================================
@dataclass
class SentSegment:
    seq: int
    end_seq: int
    payload: bytes
    time: float
    delivered: bool
    acked: bool = False
    retransmit: bool = False

    def __hash__(self):
        return self.seq

    def __eq__(self, other):
        return self.seq == other.seq


@dataclass
class RecvSegment:
    seq: int
    end_seq: int
    payload: bytes
    time: float
    in_order: bool


class TCPEndpointState:
    """
    Per-endpoint TCP state:

      TX side:
        - ip, port
        - isn, next_seq (for sending)
        - window
        - tx_fifo: SentSegment history (original + retransmits)

      RX side:
        - next_ack (RCV.NXT)
        - SACK ooseq blocks
        - rx_fifo: RecvSegment history
        - ACK policy: rx_ack_every_n, rx_ack_timeout

      Fast retransmit (sender side):
        - last_cum_ack
        - dup_ack_count
    """

    def __init__(self, ip, port, isn=None, mss=536, init_window=65535, name="endpoint",
                 rx_ack_every_n=None, rx_ack_timeout=None, start_time=0.0,
                 sack_permitted=False, max_tx_buffer=None, max_rx_buffer=None,
                 recv_capacity=None, app_read_rate=0.0):

        self.ip = ip
        self.port = port
        self.name = name

        self.isn = isn if isn is not None else random.randint(1000, 2 ** 31 - 1)

        # ----------------------------------------------------
        # TX
        # ----------------------------------------------------
        self.next_seq = self.isn

        # If we model a receive buffer, use that as the advertised window.
        # Otherwise keep the init_window behaviour.
        self.recv_capacity = recv_capacity if recv_capacity is not None else init_window
        self.recv_used = 0
        self.window = self.recv_capacity

        # Application-side "read" rate from the receive buffer (bytes/second)
        self.app_read_rate = float(app_read_rate) if app_read_rate else 0.0
        self.last_app_read_time = float(start_time)

        self.tx_window_full = False
        self.tx_window_size = None # Initialize during connection setup

        self.mss = mss
        # ----------------------------------------------------
        # RX
        # ----------------------------------------------------
        self.next_ack = 0
        self.rx_ack_every_n = rx_ack_every_n if rx_ack_every_n and rx_ack_every_n > 0 else None
        self.rx_ack_timeout = float(rx_ack_timeout) if rx_ack_timeout is not None else None
        self.rx_unacked_pkts = 0
        self.rx_last_ack_time = float(start_time)

        # SACK
        self.sack_permitted = bool(sack_permitted)
        self.rx_ooseq_blocks = []  # list of (start, end)

        # Fast retransmit tracking
        self.last_cum_ack = 0
        self.dup_ack_count = 0

        # FIFOs
        self.tx_fifo = deque()
        self.rx_fifo = deque()
        self.max_tx_buffer = max_tx_buffer
        self.max_rx_buffer = max_rx_buffer

    # --------------------------------------------------------
    # Receive buffer and application consumption
    # --------------------------------------------------------
    def _app_maybe_read(self, now):
        """
        Simulate the application reading from the socket receive buffer
        at a given rate (bytes/second). This updates recv_used + window.
        """
        if self.recv_capacity is None or self.app_read_rate <= 0:
            self.last_app_read_time = float(now)
            return

        now = float(now)
        dt = max(0.0, now - self.last_app_read_time)
        if dt <= 0:
            return

        can_read = int(self.app_read_rate * dt)
        if can_read <= 0 or self.recv_used <= 0:
            self.last_app_read_time = now
            return

        consumed = min(can_read, self.recv_used)
        self.recv_used -= consumed
        self.last_app_read_time = now

        logger.debug(f"App read {consumed} bytes from recv buffer")

        # Advertised window is "how much free space I have"
        # if self.window ==0:
        #     free_space = self.recv_capacity - self.recv_used
        #     if free_space < min(self.mss, self.recv_capacity//2):
        #         self.window = 0
        # else:
        self.window = max(0, self.recv_capacity - self.recv_used)

    def force_app_read(self, now, num_bytes=None):
        """
        Force a synchronous application read:
        - if num_bytes is None, read everything from the buffer.
        - otherwise, consume num_bytes.
        """
        if self.recv_capacity is None:
            return

        if num_bytes is None:
            self.recv_used = 0
        else:
            self.recv_used = max(0, self.recv_used - int(num_bytes))

        self.last_app_read_time = float(now)
        self.window = max(0, self.recv_capacity - self.recv_used)


    # --------------------------------------------------------
    # FIFO helpers
    # --------------------------------------------------------
    def _trim_tx_fifo(self):
        if self.max_tx_buffer is None:
            return
        while len(self.tx_fifo) > self.max_tx_buffer:
            self.tx_fifo.popleft()

    def _trim_rx_fifo(self):
        if self.max_rx_buffer is None:
            return
        while len(self.rx_fifo) > self.max_rx_buffer:
            self.rx_fifo.popleft()

    def register_sent_segment(self, seq, payload, when, delivered, retransmit):
        seg = SentSegment(
            seq=seq,
            end_seq=seq + len(payload),
            payload=payload,
            time=float(when),
            delivered=bool(delivered),
            retransmit=bool(retransmit),
        )
        self.tx_fifo.append(seg)
        self._trim_tx_fifo()
        return seg

    def register_received_segment(self, seq, payload, when, in_order_hint):
        seg = RecvSegment(
            seq=seq,
            end_seq=seq + len(payload),
            payload=payload,
            time=float(when),
            in_order=bool(in_order_hint),
        )
        self.rx_fifo.append(seg)
        self._trim_rx_fifo()
        return seg

    def mark_acked_upto(self, ack_seq):
        """
        Mark all segments with end_seq <= ack_seq as cumulatively ACKed.
        """
        acked_segments = []
        for seg in self.tx_fifo:
            if not seg.acked and seg.end_seq <= ack_seq:
                seg.acked = True
                acked_segments.append(seg)
        return acked_segments

    def get_unacked_segments(self):
        # IMPORTANT: do not filter by delivered; lost ones must still be candidates
        return [seg for seg in self.tx_fifo if not seg.acked]

    # --------------------------------------------------------
    # SACK helpers
    # --------------------------------------------------------
    def _merge_ooseq_blocks(self):
        if not self.rx_ooseq_blocks:
            return
        blocks = sorted(self.rx_ooseq_blocks, key=lambda x: x[0])
        merged = [blocks[0]]
        for s, e in blocks[1:]:
            ms, me = merged[-1]
            if s <= me:
                merged[-1] = (ms, max(me, e))
            else:
                merged.append((s, e))
        self.rx_ooseq_blocks = merged

    def _absorb_contiguous_ooseq(self):
        changed = True
        while changed:
            changed = False
            for i, (s, e) in enumerate(self.rx_ooseq_blocks):
                if s == self.next_ack:
                    self.next_ack = e
                    del self.rx_ooseq_blocks[i]
                    changed = True
                    break

    def get_sack_blocks(self, max_blocks=3):
        """
        Return up to max_blocks SACK blocks (highest first).
        Each block is a (start, end) tuple.
        """
        if not self.rx_ooseq_blocks:
            return []
        blocks = sorted(self.rx_ooseq_blocks, key=lambda x: x[0], reverse=True)
        return blocks[:max_blocks]

    # --------------------------------------------------------
    # RX data + ACK policy
    # --------------------------------------------------------
    def note_data_received(self, now, seq, payload):
        length = len(payload)

        # Application may have consumed something since last time we looked
        self._app_maybe_read(now)

        # Occupy the receive buffer with the newly delivered bytes
        if self.recv_capacity is not None:
            self.recv_used = min(self.recv_capacity, self.recv_used + length)
            #self.window = max(0, self.recv_capacity - self.recv_used)
            #buffer_space = max(0, self.recv_capacity - self.recv_used)


        self.rx_unacked_pkts += 1
        seg_end = seq + length

        in_order = (seq == self.next_ack)
        self.register_received_segment(seq, payload, now, in_order_hint=in_order)

        if seq == self.next_ack:
            self.next_ack = seg_end
            self._absorb_contiguous_ooseq()
        elif seq > self.next_ack:
            self.rx_ooseq_blocks.append((seq, seg_end))
            self._merge_ooseq_blocks()
        else:
            if seg_end > self.next_ack:
                self.next_ack = seg_end
                self._absorb_contiguous_ooseq()

    def should_send_ack(self, now):
        cond_n = self.rx_ack_every_n and self.rx_unacked_pkts >= self.rx_ack_every_n
        cond_t = self.rx_ack_timeout and (now - self.rx_last_ack_time) >= self.rx_ack_timeout
        return cond_n or cond_t

    def mark_ack_sent(self, now):
        self.rx_unacked_pkts = 0
        self.rx_last_ack_time = float(now)

    def mark_sender_window_full(self, conn_id: str, time):
        if not self.tx_window_full: # this means that the window was not full before
            solutions.write_event(conn_id, time = time, solution_line="TX_WINDOW_FULL")
        self.tx_window_full = True


    def mark_sender_window_open(self, conn_id:str, time: float, win_size: int):
        if self.tx_window_full:
            solutions.write_event(conn_id, time=time, solution_line=f"TX window open, window size: {win_size}")
        self.tx_window_full = False

    # --------------------------------------------------------
    # SACK application on sender side
    # --------------------------------------------------------
    def _apply_sack_blocks(self, sack_blocks):
        """
        Use SACK blocks from the peer's ACK to mark segments as effectively
        received at the peer, even if cum ACK has not advanced yet.

        For simplicity we treat fully SACK-covered segments as 'acked=True',
        so they will not be chosen again for retransmission.
        """
        if not sack_blocks:
            return []

        newly_acked = []
        for seg in self.tx_fifo:
            if seg.acked:
                continue
            for s, e in sack_blocks:
                if seg.seq >= s and seg.end_seq <= e:
                    seg.acked = True
                    newly_acked.append(seg)
                    break
        return newly_acked

    # --------------------------------------------------------
    # ACK processing on sender side (fast retransmit + SACK)
    # --------------------------------------------------------
    def note_ack_received(self, ack_seq, sack_blocks=None):
        """
        Called on sender when an ACK is received.

        - ack_seq: cumulative ACK
        - sack_blocks: list of (start, end) tuples from SACK option, if any.

        Returns SentSegment to fast-retransmit, or None.
        """

        # Ignore backward cumulative ACKs
        if ack_seq < self.last_cum_ack:
            return None

        # New cumulative ACK
        if ack_seq > self.last_cum_ack:
            self.last_cum_ack = ack_seq
            self.dup_ack_count = 0
            self.mark_acked_upto(ack_seq)
            return None

        # Duplicate ACK
        self.dup_ack_count += 1

        unacked = self.get_unacked_segments()
        if not unacked:
            return None

        # With SACK applied, the first unacked segment in sequence space
        # should correspond to the "hole" (lost data) when SACK is present.
        # First, exploit SACK information (if present) to mark SACKed data.
        if self.sack_permitted and sack_blocks:
            sack_acked_seg_list = self._apply_sack_blocks(sack_blocks)
            if sack_acked_seg_list:
                max_sack_acked_seq_num = max(s.seq for s in sack_acked_seg_list)
                candidate_list = set([ seq for seq in unacked if seq.seq < max_sack_acked_seq_num ])
                candidate_list = sorted(candidate_list, key=lambda s: s.seq)
                logger.debug(f"SACK acked segments: {[s.seq - self.isn for s in candidate_list]}")
                return candidate_list

        # Trigger fast retransmit on 3, 6, 9, ... dupACKs
        if self.dup_ack_count >= 3 and self.dup_ack_count % 3 == 0:
            candidate = sorted(unacked, key=lambda s: s.seq)[0]
            return candidate

        return None

    def __repr__(self):
        return (f"<TCPEndpointState {self.name} {self.ip}:{self.port} "
                f"SEQ={self.next_seq} ACK={self.next_ack} "
                f"tx={len(self.tx_fifo)} rx={len(self.rx_fifo)} "
                f"sack={self.sack_permitted}>")


# ============================================================
#  TCP connection simulator
# ============================================================
class TCPConnectionSim:
    def __init__(self, client_ip, client_port, server_ip, server_port,
                 isn_client=None, isn_server=None,
                 init_client_window=65535, init_server_window=65535,
                 start_time=0.0, data_rate_c2s=50.0, data_rate_s2c=50.0,
                 ack_base_delay=0.002, handshake_gap=0.001, fin_gap=0.001,
                 ack_every_n_c2s=1, ack_timeout_c2s=None,
                 ack_every_n_s2c=1, ack_timeout_s2c=None,
                 enable_sack=True,
                 loss_prob_c2s=0.0, loss_prob_s2c=0.0,
                 loss_hook=None, rng_seed=None,
                 fast_retx=True,
                 flush_before_close=False,
                 flush_max_rounds=3,
                 # NEW: RX buffer sizes and app read rates
                 recv_capacity_client=None, recv_capacity_server=None,
                 app_read_rate_client=0.0, app_read_rate_server=0.0,
                 # NEW: zero-window probe behaviour
                 zwp_interval=0.2, max_zwp=5,
                 # NEW: MSS (used by application-level send helpers)
                 mss=1460,
                 # RTO fixed, not estimated
                 rto_timer = 0.5):

        """
        mss: Maximum Segment Size used by the new application-level
             send helpers (client_send_app_data / server_send_app_data).
             Existing send_from_client/send_from_server continue to send
             exactly one segment of the given payload each call.
        """

        if rng_seed is not None:
            random.seed(rng_seed)

        self.time = float(start_time)
        self.state = "CLOSED"
        self.packets = []
        self.lost_packets = []

        self.client = TCPEndpointState(
            ip=client_ip, port=client_port,
            isn=isn_client, init_window=init_client_window,
            mss= int(mss),
            name="client",
            rx_ack_every_n=ack_every_n_s2c,
            rx_ack_timeout=ack_timeout_s2c,
            start_time=start_time,
            sack_permitted=False,
            recv_capacity=recv_capacity_client or init_client_window,
            app_read_rate=app_read_rate_client,
        )
        self.server = TCPEndpointState(
            ip=server_ip, port=server_port,
            isn=isn_server, init_window=init_server_window,
            mss=int(mss),
            name="server",
            rx_ack_every_n=ack_every_n_c2s,
            rx_ack_timeout=ack_timeout_c2s,
            start_time=start_time,
            sack_permitted=False,
            recv_capacity=recv_capacity_server or init_server_window,
            app_read_rate=app_read_rate_server,
        )

        self.data_rate_c2s = float(data_rate_c2s)
        self.data_rate_s2c = float(data_rate_s2c)
        self.ack_base_delay = float(ack_base_delay)
        self.handshake_gap = float(handshake_gap)
        self.fin_gap = float(fin_gap)

        self.enable_sack = bool(enable_sack)

        self.loss_prob_c2s = float(loss_prob_c2s)
        self.loss_prob_s2c = float(loss_prob_s2c)
        self.loss_hook = loss_hook

        self.fast_retx = bool(fast_retx)
        self.flush_before_close = bool(flush_before_close)
        self.flush_max_rounds = int(flush_max_rounds)
        self.rto_timer = float(rto_timer)

        # MSS (single value, used in both directions by the "app write" helpers)
        self.mss_c2s = int(mss)
        self.mss_s2c = int(mss)

        # Zero-window probe configuration
        self.zwp_interval = float(zwp_interval)
        self.max_zwp = int(max_zwp)

        # used to solutions
        self.conn_id = str(uuid.uuid4())

    # --------------------------------------------------------
    # Time helpers
    # --------------------------------------------------------
    def _round_time_ms(self, t):
        return math.ceil(t * 1000) / 1000

    def _set_time(self, new_t):
        if new_t <= self.time:
            new_t = self.time + 0.001
        new_t = self._round_time_ms(new_t)
        if new_t <= self.time:
            new_t = self._round_time_ms(self.time + 0.001)
        self.time = new_t
        return new_t

    def _advance_time_exp(self, rate):
        raw = self.time + (random.expovariate(rate) if rate > 0 else 0.001)
        return self._set_time(raw)

    # --------------------------------------------------------
    # Packet creation + loss
    # --------------------------------------------------------
    def _record_packet(self, direction, pkt):
        drop = False
        if self.loss_hook:
            drop = bool(self.loss_hook(direction, pkt))
        else:
            r = random.random()
            drop = r < (self.loss_prob_c2s if direction == "c2s"
                        else self.loss_prob_s2c)

        self.packets.append(pkt)        # always record to simulate client captured packets
        if drop:
            self.lost_packets.append(pkt)
            logger.debug(f"Packet dropped: {pkt.seq - self.client.isn}")
            return False

        return True

    def _make_packet(self, src, dst, flags, seq, ack,
                     payload=b"", window=None, options=None, direction=None):
        ip = IP(src=src.ip, dst=dst.ip)
        tcp_kwargs = dict(
            sport=src.port,
            dport=dst.port,
            flags=flags,
            seq=seq,
            ack=ack,
        )
        if window is not None:
            tcp_kwargs["window"] = window
        if options is not None:
            tcp_kwargs["options"] = options

        tcp = TCP(**tcp_kwargs)

        pkt = ip / tcp / Raw(load=payload) if payload else ip / tcp
        pkt.time = self.time

        if direction:
            delivered = self._record_packet(direction, pkt)
        else:
            delivered = True
            self.packets.append(pkt)
        pkt._delivered = delivered
        return pkt

    # --------------------------------------------------------
    # SACK option builder
    # --------------------------------------------------------
    def _build_ack_options(self, sack_blocks):
        """
        Build TCP SACK option list from a list of (start, end) blocks.
        """
        if not sack_blocks:
            return None
        sack_bytes = b"".join(struct.pack("!II", int(s), int(e)) for s, e in sack_blocks)
        return [("SAck", sack_bytes)]

    # --------------------------------------------------------
    # RX delivery + ACK generation + fast retransmit trigger
    # --------------------------------------------------------
    def _deliver_and_maybe_ack(self, rx, tx, seq, payload_bytes, ack_dir, auto_ack):
        """
        rx: receiver endpoint
        tx: sender endpoint (the one that processes ACKs)
        """
        ack_pkt = None

        # Deliver data to RX endpoint (updates RCV.NXT and SACK blocks)
        rx.note_data_received(self.time, seq, payload_bytes)

        if auto_ack and rx.should_send_ack(self.time):
            self._set_time(self.time + self.ack_base_delay)
            ack_seq = rx.next_ack

            # Build SACK option (if permitted) and also pass blocks to sender
            sack_blocks = rx.get_sack_blocks() if rx.sack_permitted else None
            opts = self._build_ack_options(sack_blocks)

            announced_window = rx.window

            logger.debug(f'({self.time}) Announced window: {announced_window}')
            ack_pkt = self._make_packet(
                src=rx, dst=tx, flags="A",
                seq=rx.next_seq, ack=ack_seq,
                window=announced_window, options=opts,
                direction=ack_dir,
            )
            rx.mark_ack_sent(self.time)

            if self.fast_retx:
                candidate = tx.note_ack_received(ack_seq, sack_blocks=sack_blocks)
                if candidate is not None:
                    if isinstance(candidate, Iterable):
                        for seg in candidate:
                            solutions.write_event(self.conn_id, time = self.time,
                                                  solution_line=f"SACK retransmit: {seg.seq - tx.isn }")
                            self._fast_retransmit(tx, rx, seg, ack_dir)
                    else:
                        solutions.write_event(self.conn_id, time = self.time,
                                              solution_line= f"Fast retransmit: {candidate.seq - tx.isn}")
                        self._fast_retransmit(tx, rx, candidate, ack_dir)

        return ack_pkt

    # --------------------------------------------------------
    # Fast retransmit helper
    # --------------------------------------------------------
    def _fast_retransmit(self, tx_ep, rx_ep, sent_seg, ack_dir):
        if ack_dir == "s2c":
            direction = "c2s"
            rate = self.data_rate_c2s
        else:
            direction = "s2c"
            rate = self.data_rate_s2c

        logger.debug(f"Fast retransmit: {sent_seg.seq - tx_ep.isn }")
        self._send_data(
            src=tx_ep, dst=rx_ep,
            rate=rate, direction=direction, ack_dir=ack_dir,
            data=sent_seg.payload, flags="PA", auto_ack=True,
            seq_override=sent_seg.seq,
        )

    def _check_and_handle_RTO_segments(self, sender: TCPEndpointState):
        segments = sender.get_unacked_segments()
        segments = filter(lambda s: self.time - s.time  >= self.rto_timer, segments)
        segments = sorted(list(segments), key=lambda s: s.seq)

        if len(segments) > 0:
            return segments[0]
        return None

    # --------------------------------------------------------
    # Flow-control helper
    # --------------------------------------------------------
    def _bytes_in_flight(self, sender):
        """
        Unique bytes in flight from 'sender' (unacked data).
        Retransmissions do not add new bytes here.
        """
        total = 0
        for seg in sender.get_unacked_segments():
            total += (seg.end_seq - seg.seq)
        return total

    # --------------------------------------------------------
    # Shared data send helper (normal + retransmit)
    # --------------------------------------------------------
    def _send_data(self, src, dst, rate, direction, ack_dir,
                   data, flags="PA", auto_ack=True, seq_override=None):

        data_bytes = data if isinstance(data, (bytes, bytearray)) else data.encode()
        length = len(data_bytes)

        # Time advances for this transmission attempt
        self._advance_time_exp(rate)

        # ----------------------------------------------------
        # Sender-side flow control based on dst.window.
        # Applied only for NEW data (seq_override is None).
        # - 1-byte sends are allowed as zero-window probes.
        # - Retransmissions (seq_override) always allowed because they
        #   do not increase bytes in flight.
        # ----------------------------------------------------
        if seq_override is None and dst.window is not None:
            in_flight = self._bytes_in_flight(src)
            #allowed = dst.window - in_flight
            allowed = src.tx_window_size - in_flight

            if allowed <= 0:
                # Allow a 1-byte probe even if window == 0
                if length == 1:
                    allowed = 1
                else:
                    # Block new data; only time passes
                    self._advance_time_exp(rate)
                    return None, None

            if length > allowed:
                if allowed <= 0:
                    self._advance_time_exp(rate)
                    return None, None
                data_bytes = data_bytes[:allowed]
                length = len(data_bytes)

            if length == allowed:
                self.client.mark_sender_window_full(conn_id=self.conn_id, time=self.time)

        seq = src.next_seq if seq_override is None else seq_override
        ack_val = src.next_ack

        pkt = self._make_packet(
            src=src, dst=dst, flags=flags,
            seq=seq, ack=ack_val,
            payload=data_bytes, window=src.window,
            direction=direction,
        )

        src.register_sent_segment(
            seq=seq, payload=data_bytes, when=self.time,
            delivered=pkt._delivered, retransmit=(seq_override is not None),
        )

        if seq_override is None:
            src.next_seq += length

        ack_pkt = None
        if pkt._delivered:
            ack_pkt = self._deliver_and_maybe_ack(
                rx=dst, tx=src,
                seq=seq, payload_bytes=data_bytes,
                ack_dir=ack_dir, auto_ack=auto_ack,
            )
            if ack_pkt.window >0:
                self.client.mark_sender_window_open(self.conn_id, self.time, ack_pkt.window)

        # for solutions
        if not pkt._delivered:
            solutions.write_event(self.conn_id, time= self.time,
                                  solution_line=f"Segment lost: {pkt.seq - self.client.isn}")

        return pkt, ack_pkt


    def _handle_zero_window_block(self, sender, receiver,
                                  direction, ack_dir,
                                  pattern_byte, rate):
        """
        Generic ZWP behaviour:
        - While receiver.window == 0:
            * advance time by zwp_interval,
            * let receiver's app read from its buffer,
            * send a 1-byte probe (if allowed by _send_data),
            * receiver replies with ACK carrying current window.
        Stops when window opens or when max_zwp is reached.
        """
        probes = 0
        logger.debug("Zero-window block started")
        while receiver.window == 0 and probes < self.max_zwp:
            # Simulate time passing with no data
            self._set_time(self.time + self.zwp_interval)
            logger.debug(f"Zero-window block: {probes}")
            # Application draining receive buffer on receiver side
            receiver._app_maybe_read(self.time)

            # 1-byte probe
            probe_payload = self._build_app_payload(1, pattern_byte)
            self._send_data(
                src=sender, dst=receiver,
                rate=rate, direction=direction, ack_dir=ack_dir,
                data=probe_payload, flags="PA", auto_ack=True,
                seq_override=None,
            )

            probes += 1

            # After the probe + ACK, receiver.window may have increased
            if receiver.window > 0:
                break


    # --------------------------------------------------------
    # Handshake
    # --------------------------------------------------------
    def open_connection(self):
        if self.state != "CLOSED":
            raise RuntimeError("Connection not CLOSED")

        c, s = self.client, self.server
        syn_opts = [("SAckOK", "")] if self.enable_sack else None

        # SYN (client -> server)
        self._set_time(self.time)
        self._make_packet(c, s, "S", seq=c.next_seq, ack=0,
                          window=c.window, options=syn_opts)

        # SYN-ACK (server -> client)
        self._set_time(self.time + self.handshake_gap)
        s.next_seq = s.isn
        synack = self._make_packet(
            s, c, "SA", seq=s.next_seq, ack=c.next_seq + 1,
            window=s.window, options=syn_opts,
        )
        s.mark_ack_sent(synack.time)

        # ACK (client -> server)
        self._set_time(self.time + self.handshake_gap)
        c.next_ack = s.next_seq + 1
        ackp = self._make_packet(
            c, s, "A", seq=c.next_seq + 1, ack=c.next_ack,
            window=c.window,
        )
        c.mark_ack_sent(ackp.time)

        # Data-phase initialization
        c.next_seq = c.isn + 1      # first client data SEQ
        s.next_seq = s.isn + 1      # first server data SEQ
        s.next_ack = c.isn + 1      # server expects client data here
        c.next_ack = s.isn + 1      # client expects server data here

        if self.enable_sack:
            c.sack_permitted = True
            s.sack_permitted = True

        # setup windows announced size
        c.tx_window_size = s.window
        s.rx_window_size = c.window

        self.state = "ESTABLISHED"

    # --------------------------------------------------------
    # Application-level helpers: "bytes written" + MSS segmentation
    # --------------------------------------------------------
    def _build_app_payload(self, length, pattern_byte):
        """
        Utility: build a pseudo-application payload of 'length' bytes,
        repeating pattern_byte.
        """
        if isinstance(pattern_byte, str):
            pattern_byte = pattern_byte.encode()
        if not pattern_byte:
            pattern_byte = b"D"
        reps = length // len(pattern_byte) + 1
        return (pattern_byte * reps)[:length]

    def client_send_app_data(self, num_bytes,
                             pattern_byte=b"D",
                             auto_ack=True,
                             use_probes=True):
        """
        General-purpose "application write" on the client side:
        - num_bytes: how many bytes the app wants to write.
        - Segments using MSS (self.mss_c2s).
        - Limited by server.window (receive buffer / flow control).
        - If blocked by zero-window, optionally runs zero-window
          probes + waits for window update, then resumes.

        Returns list of (pkt, ack_pkt) pairs (some entries may be (None, None)
        if a send attempt was blocked).
        """
        if self.state != "ESTABLISHED":
            raise RuntimeError("Connection not established")

        remaining = int(num_bytes)
        results = []

        while remaining > 0:
            rto_segment = self._check_and_handle_RTO_segments(self.client)
            if rto_segment is not None:
                # RTO retransmission detected -> retransmit on the client side: FORCED no data loss!!
                orig_c2s = self.loss_prob_c2s
                self.loss_prob_c2s = 0.0
                logger.debug(f"RTO segment detected: {rto_segment.seq - self.client.isn} ({self.time}) server window size {self.server.window}")
                pkt, ack = self.client_retransmit(seq= rto_segment.seq, data= rto_segment.payload)
                solutions.write_event(self.conn_id, time= pkt.time,
                                      solution_line= f"RTO retransmission - segment seq: {rto_segment.seq - self.client.isn}")
                self.loss_prob_c2s = orig_c2s   # restore original loss probability
                results.append((pkt, ack))
                continue
            else:
                seg_len = min(self.mss_c2s, remaining, self.client.tx_window_size)
                payload = self._build_app_payload(seg_len, pattern_byte)
                pkt, ack = self.send_from_client(payload, auto_ack=auto_ack)
                seg_len = len(pkt['TCP'].payload) if pkt is not None else 0
                #print(seg_len,  len(pkt.payload))

            results.append((pkt, ack))

            if pkt is None:
                #self.client.mark_sender_window_full(conn_id=self.conn_id, time=self.time)
                # Blocked by flow control (likely server.window == 0)
                #logger.info(f"Blocked by flow control server.window = {self.server.window}")
                if use_probes and (self.client.tx_window_size <= 1):  #or self._bytes_in_flight(self.client)>0
                    self._handle_zero_window_block(
                        sender=self.client,
                        receiver=self.server,
                        direction="c2s", ack_dir="s2c",
                        pattern_byte=pattern_byte,
                        rate=self.data_rate_c2s,
                    )
                    # If the server window opened, try again (do not
                    # decrease 'remaining' yet).
                    if self.server.window > 0:
                        logger.debug(f"Resuming send after ZWP {self.time}")
                        continue
                # Still blocked or probes disabled -> stop here
                    #break
            else:
                if ack is not None and ack.window >0:
                    self.client.tx_window_size = ack.window
                    self.client.mark_sender_window_open(conn_id=self.conn_id, time= self.time, win_size=ack.window)
                logger.debug(f'Remaining {remaining} {self.time} - Sent {pkt.seq - self.client.isn} - len {seg_len} - Acked {ack is not None}')
                # Successfully sent seg_len bytes of new data
                remaining -= seg_len


        while len(self.client.get_unacked_segments())> 0:
            self.time = round(self.time + 0.1, 3)

            rto_segment = self._check_and_handle_RTO_segments(self.client)
            if rto_segment is not None:
                self.loss_prob_c2s = 0.0
                logger.debug(
                    f"RTO segment detected: {rto_segment.seq - self.client.isn} ({self.time}) server window size {self.server.window}")
                solutions.write_event(self.conn_id, time= self.time,
                                      solution_line= f"RTO retransmission - segment seq: {rto_segment.seq - self.client.isn}")
                pkt, ack = self.client_retransmit(seq=rto_segment.seq, data=rto_segment.payload)
                results.append((pkt, ack))


        return results

    def server_send_app_data(self, num_bytes,
                             pattern_byte=b"S",
                             auto_ack=True,
                             use_probes=True):
        """
        Mirror of client_send_app_data for server -> client direction. (NOT USED IN EXERCISES)
        """
        if self.state != "ESTABLISHED":
            raise RuntimeError("Connection not established")

        remaining = int(num_bytes)
        results = []

        while remaining > 0:
            seg_len = min(self.mss_s2c, remaining)
            payload = self._build_app_payload(seg_len, pattern_byte)

            pkt, ack = self.send_from_server(payload, auto_ack=auto_ack)
            results.append((pkt, ack))

            if pkt is None:
                if use_probes and self.client.window == 0:
                    self._handle_zero_window_block(
                        sender=self.server,
                        receiver=self.client,
                        direction="s2c", ack_dir="c2s",
                        pattern_byte=pattern_byte,
                        rate=self.data_rate_s2c,
                    )
                    if self.client.window > 0:
                        continue
                break

            remaining -= seg_len

        return results

    # --------------------------------------------------------
    # Public data send / retransmit (one segment per call)
    # --------------------------------------------------------
    def send_from_client(self, data, flags="PA", auto_ack=True):
        if self.state != "ESTABLISHED":
            raise RuntimeError("Connection not established")
        return self._send_data(
            src=self.client, dst=self.server,
            rate=self.data_rate_c2s,
            direction="c2s", ack_dir="s2c",
            data=data, flags=flags, auto_ack=auto_ack,
            seq_override=None,
        )

    def send_from_server(self, data, flags="PA", auto_ack=True):
        if self.state != "ESTABLISHED":
            raise RuntimeError("Connection not established")
        return self._send_data(
            src=self.server, dst=self.client,
            rate=self.data_rate_s2c,
            direction="s2c", ack_dir="c2s",
            data=data, flags=flags, auto_ack=auto_ack,
            seq_override=None,
        )

    def client_retransmit(self, seq, data, flags="PA", auto_ack=True):
        if self.state != "ESTABLISHED":
            raise RuntimeError("Connection not established")
        return self._send_data(
            src=self.client, dst=self.server,
            rate=self.data_rate_c2s,
            direction="c2s", ack_dir="s2c",
            data=data, flags=flags, auto_ack=auto_ack,
            seq_override=seq,
        )

    def server_retransmit(self, seq, data, flags="PA", auto_ack=True):
        if self.state != "ESTABLISHED":
            raise RuntimeError("Connection not established")
        return self._send_data(
            src=self.server, dst=self.client,
            rate=self.data_rate_s2c,
            direction="s2c", ack_dir="c2s",
            data=data, flags=flags, auto_ack=auto_ack,
            seq_override=seq,
        )

    # --------------------------------------------------------
    # Optional: flush unacked data before FIN
    # --------------------------------------------------------
    def _flush_unacked(self, sender, receiver, direction, ack_dir):
        """
        Best-effort flush of outstanding unacked data before closing.

        If flush_before_close=True, we:
          - temporarily disable loss,
          - perform up to flush_max_rounds retransmissions for all unacked segs.
        """
        if not self.flush_before_close:
            return

        orig_c2s = self.loss_prob_c2s
        orig_s2c = self.loss_prob_s2c
        self.loss_prob_c2s = 0.0
        self.loss_prob_s2c = 0.0

        rate = self.data_rate_c2s if direction == "c2s" else self.data_rate_s2c

        for _ in range(self.flush_max_rounds):
            unacked = sender.get_unacked_segments()
            if not unacked:
                break

            for seg in sorted(unacked, key=lambda s: s.seq):
                if seg.seq >= receiver.next_ack:
                    self._send_data(
                        src=sender, dst=receiver,
                        rate=rate, direction=direction, ack_dir=ack_dir,
                        data=seg.payload, flags="PA", auto_ack=True,
                        seq_override=seg.seq,
                    )
                    logging.debug(f"Flush Unacked {seg.seq - sender.isn}")

        self.loss_prob_c2s = orig_c2s
        self.loss_prob_s2c = orig_s2c

    # --------------------------------------------------------
    # Flow-control helpers (explicit window overrides)
    # --------------------------------------------------------
    def set_client_window(self, w):
        self.client.window = int(w)

    def set_server_window(self, w):
        self.server.window = int(w)

    # --------------------------------------------------------
    # Close connection (client/server side)
    # --------------------------------------------------------
    def close_by_client(self):
        if self.state not in ("ESTABLISHED", "FIN_WAIT"):
            raise RuntimeError("Cannot close now")

        c, s = self.client, self.server

        # Optional: flush outstanding client->server data
        self._flush_unacked(sender=c, receiver=s,
                            direction="c2s", ack_dir="s2c")
        self._set_time(self.time + self.fin_gap)
        self._make_packet(c, s, "FA", c.next_seq, c.next_ack,
                          window=c.window)

        self._set_time(self.time + self.fin_gap)
        self._make_packet(s, c, "FA", s.next_seq, c.next_seq + 1,
                          window=s.window)

        self._set_time(self.time + self.fin_gap)
        self._make_packet(c, s, "A", c.next_seq + 1, s.next_seq + 1,
                          window=c.window)

        self.state = "CLOSED"

    def close_by_server(self):
        if self.state not in ("ESTABLISHED", "FIN_WAIT"):
            raise RuntimeError("Cannot close now")

        c, s = self.client, self.server

        # Optional: flush outstanding server->client data
        self._flush_unacked(sender=s, receiver=c,
                            direction="s2c", ack_dir="c2s")

        self._set_time(self.time + self.fin_gap)
        self._make_packet(s, c, "FA", s.next_seq, s.next_ack,
                          window=s.window)

        self._set_time(self.time + self.fin_gap)
        self._make_packet(c, s, "FA", c.next_seq, s.next_seq + 1,
                          window=c.window)

        self._set_time(self.time + self.fin_gap)
        self._make_packet(s, c, "A", s.next_seq + 1, c.next_seq + 1,
                          window=s.window)

        self.state = "CLOSED"

        
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
@ensure_params(param_name='flow_parameters',
               required=['mss','loss_prob_c2s',
                         "app_bytes_to_send",
                         'client_ip', 'server_ip',
                         'client_port', 'server_port',
                         "app_read_rate_server"],
               generators={
                   'app_bytes_to_send': lambda: random.randint(1000, 10_000),
                   'client_port': random_high_port,
                   'server_port': random_port,
                   'client_ip': make_random_client_ip,
                   'server_ip': make_random_server_ip,
               },
               inplace=True)
def tcp_client_server_flow_generator(flow_parameters):
    conn = TCPConnectionSim(
        client_ip=flow_parameters['client_ip'],
        client_port=flow_parameters['client_port'],
        server_ip=flow_parameters['server_ip'],
        server_port=flow_parameters['server_port'],
        enable_sack=flow_parameters.get('enable_sack', False),
        loss_prob_c2s=flow_parameters['loss_prob_c2s'],
        loss_prob_s2c=0.0,
        fast_retx=flow_parameters.get('fast_retx', False),
        ack_every_n_c2s=1,
        flush_before_close=True,
        mss=flow_parameters['mss'],
        init_server_window=flow_parameters.get('init_server_window', 65535),
        recv_capacity_server=flow_parameters.get('init_server_window', 65535),
        app_read_rate_server=flow_parameters['app_read_rate_server'],
        rto_timer=flow_parameters.get('rto_timer', 1),
    )

    solutions.write(conn.conn_id, "Protocol: TCP")
    solutions.write(conn.conn_id, f"Client: {flow_parameters['client_ip']}:{flow_parameters['client_port']}")
    solutions.write(conn.conn_id, f"Server: {flow_parameters['server_ip']}:{flow_parameters['server_port']}")

    conn_params_solution_line = f"Connection params:\n"\
                                f"\tMSS: {flow_parameters['mss']}\n"\
                                f"\tServer Window Size: {conn.server.window}"
    if conn.enable_sack:
        conn_params_solution_line+=" \n\tSACK enabled"
    solutions.write(conn.conn_id, conn_params_solution_line)
    solutions.write(conn.conn_id, f"Client application bytes to send: {flow_parameters['app_bytes_to_send']} Bytes")



    conn.open_connection()
    conn.client_send_app_data(num_bytes=flow_parameters['app_bytes_to_send'])
    conn.close_by_client()
    return conn.packets
