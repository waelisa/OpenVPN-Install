OpenVPN Installer

A secure, automated OpenVPN server installer and management tool for multiple Linux distributions.

https://img.shields.io/badge/License-MIT-yellow.svg
https://img.shields.io/badge/platform-linux-blue.svg
https://img.shields.io/badge/OpenVPN-2.4+-orange.svg
📥 Quick Download
bash

# Download the script
wget https://github.com/waelisa/OpenVPN-Install/raw/refs/heads/main/openvpn-install.sh

# Make it executable
chmod +x openvpn-install.sh

# Run it (as root)
sudo ./openvpn-install.sh

✨ Features

    One-command installation - Fully automated OpenVPN server setup

    Interactive & Non-interactive modes - Perfect for both manual and automated deployments

    40+ DNS providers - Including Cloudflare, Quad9, Google, OpenDNS, AdGuard, and more

    Dual-stack support - IPv4, IPv6, or both for VPN clients

    Advanced encryption options - Full control over ciphers, curves, and protocols

    Multiple authentication modes - PKI (traditional) or Peer Fingerprint (simplified)

    Client management - Add, list, revoke, and renew certificates

    Connection monitoring - View currently connected clients with real-time stats

    Cross-distro support - Debian, Ubuntu, CentOS, Fedora, Arch Linux, and more

🚀 Supported Distributions
Distribution	Versions
Debian	11+
Ubuntu	18.04+
CentOS	8+ (Stream)
Rocky Linux	8+
AlmaLinux	8+
Fedora	Latest
Arch Linux	Latest
Amazon Linux	2023.6+
Oracle Linux	8+
openSUSE	Leap 16+ / Tumbleweed
📋 Requirements

    Root access - The script must be run as root

    TUN/TAP enabled - Required for VPN tunnel

    Internet connection - For downloading packages

    Supported OS - One of the distributions listed above

🔧 Installation
Quick Install (Interactive)
bash

curl -O https://github.com/waelisa/OpenVPN-Install/raw/refs/heads/main/openvpn-install.sh
chmod +x openvpn-install.sh
sudo ./openvpn-install.sh

This will launch the interactive menu. If OpenVPN is not installed, it will guide you through the installation process.
One-liner (for the adventurous)
bash

curl -sS https://github.com/waelisa/OpenVPN-Install/raw/refs/heads/main/openvpn-install.sh | sudo bash

🎮 Usage
Command Structure
bash

./openvpn-install.sh <command> [options]

Available Commands
Command	Description
install	Install and configure OpenVPN server
uninstall	Remove OpenVPN server
client	Manage client certificates
server	Server management
interactive	Launch interactive menu
Global Options
Option	Description
--verbose	Show detailed command output
--log <path>	Custom log file path
--no-log	Disable file logging
--no-color	Disable colored output
-h, --help	Show help
Installation Examples
bash

# Interactive installation (recommended)
sudo ./openvpn-install.sh install -i

# Non-interactive with custom port
sudo ./openvpn-install.sh install --port 443 --protocol tcp

# List all available DNS providers
sudo ./openvpn-install.sh install --dns-list

# Install with specific DNS
sudo ./openvpn-install.sh install --dns quad9 --no-client

Client Management
bash

# Add a new client
sudo ./openvpn-install.sh client add john

# Add client with password protection
sudo ./openvpn-install.sh client add jane --password

# Add client with custom output path
sudo ./openvpn-install.sh client add bob --output /home/bob/bob.ovpn

# List all clients
sudo ./openvpn-install.sh client list

# Revoke a client
sudo ./openvpn-install.sh client revoke john

# List clients in JSON format
sudo ./openvpn-install.sh client list --format json

Server Management
bash

# Check connected clients
sudo ./openvpn-install.sh server status

# Renew server certificate
sudo ./openvpn-install.sh server renew --cert-days 365

Uninstall
bash

# Interactive uninstall
sudo ./openvpn-install.sh uninstall

# Force uninstall (no prompt)
sudo ./openvpn-install.sh uninstall --force

🎛️ DNS Providers

The script supports over 40 DNS providers across multiple categories:
Category	Providers
System & Local	system, unbound
Cloudflare	cloudflare, cloudflare-malware, cloudflare-family
Quad9	quad9, quad9-uncensored, quad9-ecs
Google	google, google-ipv6
OpenDNS	opendns, opendns-familyshield
AdGuard	adguard, adguard-family
NextDNS/Control D	nextdns, controld, controld-family
CleanBrowsing	cleanbrowsing, cleanbrowsing-adult, cleanbrowsing-security
European Privacy	fdn, dnswatch, dns0, dns0-family
Yandex	yandex, yandex-safe, yandex-family
Security Focused	comodo, alternate, norton
Neustar	neustar, neustar-family, neustar-business
Legacy/Other	dyn, verisign, safe-surfer

View all with:
bash

sudo ./openvpn-install.sh install --dns-list

🔐 Security Features

    Modern encryption defaults - AES-128-GCM, ECDSA certificates

    Perfect Forward Secrecy - Using ECDHE key exchange

    Control channel encryption - tls-crypt-v2 (unique key per client)

    Certificate revocation - Full CRL support

    Authentication modes - PKI (traditional) or Peer Fingerprint (simplified)

    DNS leak protection - Built-in blocking of outside DNS

    IPv6 leak protection - Automatic IPv6 blocking when not in use

📊 Configuration Files

After installation, you'll find:

    Server config: /etc/openvpn/server/server.conf

    Client configs: ~/clientname.ovpn (in user's home directory)

    Logs: /var/log/openvpn/status.log

    Certificates: /etc/openvpn/server/easy-rsa/pki/

🚦 Client Connection

    Download the generated .ovpn file from your server

    Import into your OpenVPN client:

        Windows: OpenVPN Community Client

        macOS: Tunnelblick or Viscosity

        Linux: NetworkManager or command-line openvpn

        Android: OpenVPN Connect

        iOS: OpenVPN Connect

    Connect and enjoy secure browsing!

🔄 Updating

To update to the latest version:
bash

# Download the latest script
wget -O openvpn-install.sh https://github.com/waelisa/OpenVPN-Install/raw/refs/heads/main/openvpn-install.sh
chmod +x openvpn-install.sh

🐛 Troubleshooting
Common Issues

"TUN is not available"

    Enable TUN/TAP in your VPS control panel

    For OpenVZ, contact your provider

"Port already in use"

    Change the port during installation

    Check with netstat -tulpn | grep 1194

Client can't connect

    Check firewall rules

    Verify the server's public IP/hostname

    Ensure the client config has the correct endpoint

Logs

Check the installation log:
bash

cat openvpn-install.log

Check OpenVPN status:
bash

systemctl status openvpn-server@server
journalctl -u openvpn-server@server -f

🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

    Fork the repository

    Create your feature branch (git checkout -b feature/AmazingFeature)

    Commit your changes (git commit -m 'Add some AmazingFeature')

    Push to the branch (git push origin feature/AmazingFeature)

    Open a Pull Request

📝 License

This project is licensed under the MIT License - see the LICENSE file for details.
🙏 Acknowledgements

Based on the excellent angristan/openvpn-install script. Enhanced with additional DNS providers, encryption options, and improved user interface.
📞 Support

    Issues: GitHub Issues

    Documentation: Check the Wiki

Made with ❤️ for the Open Source community
