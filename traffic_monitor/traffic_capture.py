from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from scapy.all import IP, TCP, UDP, sniff


class TrafficMonitor:
    """Real-time traffic monitor that runs packet capture in a background thread."""

    SAFE_PORTS = {80, 443, 22, 53}
    PACKET_RATE_THRESHOLD = 100  # packets/sec
    LARGE_TRANSFER_THRESHOLD_BYTES = 10 * 1024 * 1024  # 10 MB

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._iface: str | None = None

        self.total_packets = 0
        self.total_bytes = 0
        self.max_packets_per_second = 0
        self.unusual_port_hits = 0

        self._packet_timestamps: deque[float] = deque()
        self.recent_packets: deque[dict[str, Any]] = deque(maxlen=200)

    def start(self, iface: str | None = None) -> None:
        """Start live packet capture on a background thread."""
        if self._thread and self._thread.is_alive():
            return

        self._iface = iface
        # Reset counters when starting to avoid carrying old demo values
        with self._lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.max_packets_per_second = 0
            self.unusual_port_hits = 0
            self._packet_timestamps.clear()
            self.recent_packets.clear()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop packet capture thread gracefully."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        # Reset running state and counters so GUI shows zeros when stopped
        with self._lock:
            self._thread = None
            self._iface = None
            self.total_packets = 0
            self.total_bytes = 0
            self.max_packets_per_second = 0
            self.unusual_port_hits = 0
            self._packet_timestamps.clear()
            self.recent_packets.clear()

    def _sniff_loop(self) -> None:
        """Sniff in short windows so stop signal can be honored quickly."""
        while not self._stop_event.is_set():
            sniff(
                iface=self._iface,
                prn=self._process_packet,
                store=False,
                timeout=1,
            )

    def _process_packet(self, packet: Any) -> None:
        if IP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"
        port: int | None = None

        if TCP in packet:
            protocol = "TCP"
            port = int(packet[TCP].dport)
        elif UDP in packet:
            protocol = "UDP"
            port = int(packet[UDP].dport)
        else:
            protocol = str(packet[IP].proto)

        packet_size = len(packet)
        now = time.time()

        with self._lock:
            self.total_packets += 1
            self.total_bytes += packet_size
            self._packet_timestamps.append(now)

            while self._packet_timestamps and now - self._packet_timestamps[0] > 1:
                self._packet_timestamps.popleft()

            current_pps = len(self._packet_timestamps)
            if current_pps > self.max_packets_per_second:
                self.max_packets_per_second = current_pps

            if port is not None and port not in self.SAFE_PORTS:
                self.unusual_port_hits += 1

            self.recent_packets.append(
                {
                    "timestamp": now,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "protocol": protocol,
                    "port": port,
                    "packet_size": packet_size,
                }
            )

    def _calculate_behavior_score(self) -> int:
        """Return 0-100 score where higher means more suspicious behavior."""
        with self._lock:
            total_packets = self.total_packets
            total_bytes = self.total_bytes
            max_pps = self.max_packets_per_second
            unusual_port_hits = self.unusual_port_hits

        pps_score = 0.0
        if max_pps > self.PACKET_RATE_THRESHOLD:
            pps_score = min(40.0, (max_pps - self.PACKET_RATE_THRESHOLD) * 0.5)

        unusual_ratio = (unusual_port_hits / total_packets) if total_packets else 0.0
        unusual_port_score = min(30.0, unusual_ratio * 100.0)

        data_transfer_score = 0.0
        if total_bytes > self.LARGE_TRANSFER_THRESHOLD_BYTES:
            overshoot = total_bytes - self.LARGE_TRANSFER_THRESHOLD_BYTES
            data_transfer_score = min(30.0, 15.0 + (overshoot / (1024 * 1024)) * 1.5)

        total_score = pps_score + unusual_port_score + data_transfer_score
        return int(max(0, min(100, round(total_score))))

    def get_metrics(self) -> dict[str, Any]:
        """Return current session metrics and suspicious-pattern indicators."""
        with self._lock:
            current_pps = len(self._packet_timestamps)
            total_packets = self.total_packets
            total_bytes = self.total_bytes
            max_pps = self.max_packets_per_second
            unusual_port_hits = self.unusual_port_hits

        large_transfer = total_bytes > self.LARGE_TRANSFER_THRESHOLD_BYTES
        high_packet_rate = max_pps > self.PACKET_RATE_THRESHOLD

        return {
            "capture_running": bool(self._thread and self._thread.is_alive()),
            "interface": self._iface,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "data_volume_mb": round(total_bytes / (1024 * 1024), 3),
            "packets_per_second": current_pps,
            "max_packets_per_second": max_pps,
            "unusual_port_hits": unusual_port_hits,
            "suspicious_patterns": {
                "high_packet_rate": high_packet_rate,
                "unusual_ports_detected": unusual_port_hits > 0,
                "large_data_transfer": large_transfer,
            },
            "traffic_behavior_score": self._calculate_behavior_score(),
            "recent_packets": list(self.recent_packets),
        }


if __name__ == "__main__":
    monitor = TrafficMonitor()
    monitor.start()  # default interface

    print("Traffic monitor started. Collecting for 10 seconds...")
    time.sleep(10)

    stats = monitor.get_metrics()
    monitor.stop()

    print("Traffic monitor stopped.")
    print(stats)
