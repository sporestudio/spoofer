# SPOOFER

A Python-based desktop application for performing ARP spoofing and DNS spoofing attacks in a local network. Built with **Tkinter** for the GUI, **Scapy** for packet crafting/sniffing, and structured using the **Strategy** and **Builder** design patterns.

---

## Features

- **Network Scanning**: Discover live hosts on the local `/24` network via ARP.  
- **ARP Spoofing**: Poison ARP caches of victim and gateway to intercept traffic.  
- **DNS Spoofing**: Intercept DNS queries and reply with attacker-controlled IPs.  
- **Internet Blocking**: Isolate a victim by spoofing only gateway replies.  
- **Modular Architecture**:  
  - **Strategy Pattern** for interchangeable attack behaviors.  
  - **Builder Pattern** for clear construction of complex strategies.  
  - **Logger** abstraction to unify console and GUI logging.  

---

## Table of Contents

- [Prerequisites](#prerequisites)  
- [Installation](#installation)  
- [Directory Structure](#directory-structure)  
- [Usage](#usage)  
- [Design Patterns](#design-patterns)  
- [Ethical Warning](#ethical-warning)  

---

## Prerequisites

- Python 3.8+  
- Administrator/root privileges (to send raw packets)  
- Dependencies listed in `requirements.txt`:
  ```text
  scapy
  netifaces
  ```

## Installation

#### Clone repository:

```bash
$ git clone https://github.com/tu_usuario/arp_dns_spoofing_tool.git
$ cd arp_dns_spoofing_tool
```

#### Install dependencies:

```bash
$ pip install -r requirements.txt
```

#### Run the application:

```bash
$ python src/main.py
```

## Directory Structure

arp_dns_spoofing_tool/
├── README.md             # This file
├── requirements.txt      # Python dependencies
├── docs/                 # Design documentation, UML diagrams
│   └── design.md
└── src/                  # Source code
    ├── main.py           # Entry point: launches GUI
    ├── gui/              # GUI package
    │   ├── __init__.py
    │   └── gui_app.py    # Tkinter interface and controllers
    └── core/             # Core functionality
        ├── __init__.py
        ├── attack_manager.py  # Strategy context
        ├── network_tools.py   # IP/MAC utilities and scanning
        ├── logger.py          # Logging abstraction
        ├── strategies/        # Concrete Strategy implementations
        │   ├── __init__.py
        │   ├── strategy.py
        │   ├── arp_spoof.py
        │   ├── dns_spoof.py
        │   └── block_internet.py
        └── builders/          # Builder classes for strategies
            ├── __init__.py
            └── arp_spoof_builder.py



## Design Patterns

- Strategy Pattern: AttackStrategy interface with concrete strategies:

    - `ArpSpoofStrategy`
    - `DnsSpoofStrategy`
    - `BlockInternetStrategy`

- Builder Pattern: `ArpSpoofBuilder` for clear, step-by-step instantiation of ArpSpoofStrategy with parameter validation.

- Logger Abstraction: Single Logger class to decouple logging from GUI and core logic.

## Ethical Warning

This tool is intended only for educational purposes and authorized penetration testing in controlled environments. Unauthorized use may be illegal and unethical. Always obtain explicit permission before testing on any network.

<br>

> *Developed by [sporestudio](https://github.com/sporestudio) — Use responsibly*.

