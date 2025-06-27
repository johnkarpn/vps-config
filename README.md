# VPS Setup Script

An automated script to configure a VPS server by installing and setting up essential components:

- **AdGuard Home** — a local DNS filter for blocking ads and trackers.
- **3X UI** — a web management panel for V2Ray and related services.
- **WireGuard** — a modern, fast, and easy-to-configure VPN.
- **nftables** — a firewall solution to secure your server.

All web services (AdGuard and 3X UI) run behind an **nginx** reverse proxy, with the option to obtain and automatically renew SSL certificates via **Let's Encrypt**.

---

## Features

- Interactive configuration of parameters (ports, domains, passwords, network interfaces).
- Support for both IPv4 and IPv6, with the ability to disable IPv6.
- Automatic generation of random passwords and access paths for the 3X UI panel.
- Secure access setup via public SSH key and fail2ban.
- Flexible WireGuard configuration with client-specific settings.
- nftables firewall rules setup for traffic filtering.

---

## Requirements

- VPS running Ubuntu (recommended: latest LTS version).
- Domain name for HTTPS setup (optional but recommended).
- Public SSH key for secure access.
- Basic Linux command line skills.

---

## Quick Start

Run the installer with:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/johnkarpn/vps-config/master/install.sh)
