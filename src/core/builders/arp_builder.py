#!/usr/bin/env python3

"""
ARP Builder Module
-----------------

This module provides a builder class for constructing ARP packets.
It allows for easy creation of ARP requests and replies with specified parameters.
"""

from logger import Logger
from strategies import ArpSpoofingStrategy

class ArpBuilder:
    def __init__(self, logger: Logger):
        """
        Initializes the ARP Builder with a logger instance.

        :param logger: Logger instance for logging events.
        """
        self._target_ip = None
        self._gateway_ip = None
        self._target_mac = None
        self._gateway_mac = None
        self._logger = logger

    def set_target_ip(self, target_ip: str) -> 'ArpBuilder':
        """
        Sets the target IP address for the ARP packet.

        :param target_ip: The target IP address.
        :return: The current instance of ArpBuilder for method chaining.
        """
        self._target_ip = target_ip
        self._logger.log(f"Target IP set to {target_ip}")
        return self
    
    def set_gateway_ip(self, gateway_ip: str) -> 'ArpBuilder':
        """
        Sets the gateway IP address for the ARP packet.

        :param gateway_ip: The gateway IP address.
        :return: The current instance of ArpBuilder for method chaining.
        """
        self._gateway_ip = gateway_ip
        self._logger.log(f"Gateway IP set to {gateway_ip}")
        return self
    
    def set_target_mac(self, target_mac: str) -> 'ArpBuilder':
        """
        Sets the target MAC address for the ARP packet.

        :param target_mac: The target MAC address.
        :return: The current instance of ArpBuilder for method chaining.
        """
        self._target_mac = target_mac
        self._logger.log(f"Target MAC set to {target_mac}")
        return self
    
    def set_gateway_mac(self, gateway_mac: str) -> 'ArpBuilder':
        """
        Sets the gateway MAC address for the ARP packet.

        :param gateway_mac: The gateway MAC address.
        :return: The current instance of ArpBuilder for method chaining.
        """
        self._gateway_mac = gateway_mac
        self._logger.log(f"Gateway MAC set to {gateway_mac}")
        return self
    
    def build(self) -> ArpSpoofingStrategy:
        """
        Builds the ARP spoofing strategy with the specified parameters.

        :return: An instance of ArpSpoofingStrategy configured with the provided parameters.
        """
        if not all([self._target_ip, self._gateway_ip, self._target_mac, self._gateway_mac]):
            raise ValueError("All parameters (target IP, gateway IP, target MAC, gateway MAC) must be set before building.")
        
        self._logger.log("Building ARP spoofing strategy...")
        return ArpSpoofingStrategy(
            target_ip=self._target_ip,
            gateway_ip=self._gateway_ip,
            target_mac=self._target_mac,
            gateway_mac=self._gateway_mac,
            logger=self._logger
        )
