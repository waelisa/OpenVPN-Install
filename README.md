# **Secure OpenVPN Server Installer (Advanced Version)**

A high-performance, security-hardened OpenVPN server installer for Linux. This version is a significant fork of the original Angristan script, featuring an expanded DNS library, modern OpenVPN 2.6+ features, and enhanced cleanup logic.

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![https://img.shields.io/badge/OpenVPN-2.4+-orange.svg)](https://img.shields.io/badge/OpenVPN-2.4+-orange.svg)
[![Transmission](https://img.shields.io/badge/Transmission-4-orange.svg)](https://transmissionbt.com/) 

## **📥 Quick Download & Install**

bash

# Download 

wget https://github.com/waelisa/OpenVPN-Install/raw/refs/heads/main/openvpn-install.sh -O openvpn-install.sh

chmod +x openvpn-install.sh

sudo ./openvpn-install.sh

## **🌟 Key Enhancements in this Version**

**Feature**

**Description**

**🧹 Complete Client Cleanup**

Fixed revokeClient and uninstall logic. Script now recursively searches and removes .ovpn files from /root/ and /home/ directories.

**🌐 Massive DNS Library**

40+ pre-configured DNS providers across 14 categories

**🔐 OpenVPN 2.6+ Support**

Peer Fingerprint authentication mode and latest TLS 1.3 ciphersuites

**🌍 Improved Networking**

Automatic IPv4/IPv6 detection with custom subnet support

**⚡ Advanced Encryption**

Full control over ciphers, curves, and protocols

**🔄 Zero-Downtime Renewals**

Server certificate renewal without client reconfiguration

## **🖥️ Supported Operating Systems**

**Distribution**

**Supported Versions**

**Debian** 11, 12

**Ubuntu** 20.04, 22.04, 24.04

**CentOS / Rocky / Alma** 8, 9

**Fedora** 

Latest

**Arch Linux** 

**Amazon Linux** 2023.6+

**Oracle Linux** 8+

**openSUSE**

Leap 16+ / Tumbleweed

## **🚀 Usage Examples**

### **Installation Modes**

bash

wget -O openvpn-install.sh https://github.com/waelisa/OpenVPN-Install/raw/refs/heads/main/openvpn-install.sh && chmod +x openvpn-install.sh && sudo ./openvpn-install.sh

# Interactive installation (asks all questions)

sudo ./openvpn-install.sh install -i

# Non-interactive with custom settings

sudo ./openvpn-install.sh install --port 443 --protocol tcp --dns quad9

# List all available DNS providers

sudo ./openvpn-install.sh install --dns-list

### **Client Management**

bash

# Add a new client

sudo ./openvpn-install.sh client add john

# Add client with password protection

sudo ./openvpn-install.sh client add jane --password

# List all client

ssudo ./openvpn-install.sh client list

# Revoke a client (automatically removes .ovpn files)

sudo ./openvpn-install.sh client revoke john

# List clients in JSON format

sudo ./openvpn-install.sh client list --format json

### **Server Management**

bash

# Check connected clients

sudo ./openvpn-install.sh server status

# Renew server certificate

sudo ./openvpn-install.sh server renew --cert-days 365

# Complete uninstall (revokes all clients, removes all .ovpn files)

sudo ./openvpn-install.sh uninstall

## **🎛️ DNS Providers (40+ Options)**

**Category**

**Providers**

**🖥️ System & Local**

system, unbound

**☁️ Cloudflare**

cloudflare, cloudflare-malware, cloudflare-family

**🛡️ Quad9**

quad9, quad9-uncensored, quad9-ecs

**🔍 Google**

google, google-ipv6

**🏢 OpenDNS**

opendns, opendns-familyshield

**🚫 AdGuard**

adguard, adguard-family

**⚙️ NextDNS/Control D**

nextdns, controld, controld-family

**👪 CleanBrowsing**

cleanbrowsing, cleanbrowsing-adult, cleanbrowsing-security

**🇪🇺 European Privacy**

fdn, dnswatch, dns0, dns0-family

**🇷🇺 Yandex**

yandex, yandex-safe, yandex-family

**🔒 Security Focused**

comodo, alternate, norton

**⚡ Neustar**

neustar, neustar-family, neustar-business

**📜 Legacy**

dyn, verisign, safe-surfer

**✏️ Custom**

custom (manual entry)

## **🔐 Security Features**

**Feature**

**Description**

**Modern Encryption**

AES-128/256-GCM, CHACHA20-POLY1305

**Perfect Forward Secrecy**

ECDHE key exchange with multiple curve options

**Control Channel Security**

tls-crypt-v2 (unique key per client)

**Certificate Management**

Full CRL support with automatic renewal

**Authentication Modes**

PKI (traditional) or Peer Fingerprint (simplified)

**DNS Leak Protection**

Built-in blocking of outside DNS

**IPv6 Leak Protection**

Automatic IPv6 blocking when not in use

## **📊 Configuration Files**

**File**

**Location**

**Server Config**

/etc/openvpn/server/server.conf

**Client Configs**

\~/clientname.ovpn (user's home)

**Logs**

/var/log/openvpn/status.log

**Certificates**

/etc/openvpn/server/easy-rsa/pki/

## **🔧 Advanced Features**

### **Complete Encryption Customization**

When you select "y" during encryption customization, you get full control over:

*   **Cipher Selection**: AES-128/256-GCM, CHACHA20-POLY1305, legacy CBC
*   **Certificate Type**: ECDSA (with prime256v1/secp384r1/secp521r1) or RSA (2048/3072/4096)
*   **Control Channel**: Multiple cipher options for TLS handshake
*   **TLS Version**: 1.2 or 1.3
*   **TLS 1.3 Cipher Suites**: All secure, AES-256 only, AES-128 only, or ChaCha20 only
*   **Key Exchange Groups**: X25519, NIST curves, or all modern curves
*   **HMAC Algorithm**: SHA256, SHA384, or SHA512
*   **TLS Signature Mode**: tls-crypt-v2 (recommended), tls-crypt, or tls-auth

### **Cleanup Improvements**

*   **Revoke Client**: Automatically removes .ovpn files from /home/\*/ and /root/
*   **Uninstall**: Revokes all clients, removes all .ovpn files, cleans firewall rules, and purges packages

## **📝 Changelog**

### **Version 2.0 (Current)**

*   ✅ Fixed client revocation - now removes .ovpn files
*   ✅ Enhanced uninstall - revokes all clients and cleans up
*   ✅ Added 40+ DNS providers with categories
*   ✅ Added Peer Fingerprint authentication (OpenVPN 2.6+)
*   ✅ Improved IPv4/IPv6 detection
*   ✅ Added complete encryption customization menu

### **Version 1.0 (Original)**

*   Base Angristan OpenVPN installer

## **🤝 Contributing**

Contributions are welcome! Please feel free to submit a Pull Request.

1.  Fork the repository
2.  Create your feature branch (git checkout -b feature/AmazingFeature)
3.  Commit your changes (git commit -m 'Add some AmazingFeature')
4.  Push to the branch (git push origin feature/AmazingFeature)
5.  Open a Pull Request

## **📜 License**

This project is licensed under the MIT License file for details.

## **🙏 Acknowledgements**

## **📞 Support**

*   **Issues**: [GitHub Issues](https://github.com/waelisa/OpenVPN-Install/issues)
*   **Wiki**: [Documentation](https://github.com/waelisa/OpenVPN-Install/wiki)

**Made with ❤️ for the Open Source community**

[Donate link – PayPal](https://www.paypal.me/WaelIsa)
