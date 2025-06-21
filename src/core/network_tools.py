#!/usr/bin/env python3

"""
Network Tools Module
-----------------

This module provides utility functions for network operations,
such as sending ARP packets and checking if a host is reachable.
"""

import netifaces
from scapy.all import ARP, Ether, srp, get_if_addr, conf


class NetworkTools:
    def __init__(self):
        """
        Initializes the NetworkTools instance.
        """
        pass

    def get_local_ip(self) -> str:
        """
        Retrieves the local IP address of the machine.

        :return: The local IP address as a string.
        """
        return get_if_addr(conf.iface)

    def get_gateway_ip(self) -> str:
        """
        Retrieves the default gateway IP address.

        :return: The default gateway IP address as a string.
        """
        gateways = netifaces.gateways()
        return gateways['default'][netifaces.AF_INET][0]
    
    def get_mac(self, ip: str) -> str:
        """
        Retrieves the MAC address of a given IP address.

        :param ip: The IP address to look up.
        :return: The MAC address as a string.
        """
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(broadcast / arp_request, timeout=2, verbose=False)[0]

        if result:
            return result[0][1].hwsrc
        return None
    
    def scan_network(self, cdir: str) -> str:
        """
        Scans the network for active hosts in the given CIDR range.
        """
        arp_request = ARP(pdst=cdir)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        result = srp(packet, timeout=3, verbose=False)[0]

        hosts = []
        for _, received in result:
            hosts.append((received.psrc, received.hwsrc))

        return hosts