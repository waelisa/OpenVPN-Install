# Secure OpenVPN Server Installer (Advanced Version)

A high-performance, security-hardened OpenVPN server installer for Linux. This version is a significant fork of the original Angristan script, featuring an expanded DNS library, modern OpenVPN 2.6+ features, and enhanced cleanup logic.



## 🌟 Key Enhancements in this Version

* **Complete Client Cleanup**: Fixed `revokeClient` and `uninstall` logic. The script now recursively searches and removes `.ovpn` files from both `/root/` and `/home/` directories to ensure no leftover config files remain.
* **Massive DNS Library**: Includes over 30 pre-configured DNS providers categorized by:
  - **Security Focused**: Quad9, Cloudflare Malware, Comodo.
  - **Privacy Focused**: DNS0.eu, DNS.WATCH, FDN.
  - **Family Protection**: AdGuard Family, CleanBrowsing, Yandex Safe.
* **OpenVPN 2.6+ Support**: Includes support for **Peer Fingerprint** authentication mode and the latest TLS 1.3 ciphersuites like `TLS_CHACHA20_POLY1305_SHA256`.
* **Improved Networking**: Automatic detection of IPv4 and IPv6 with support for custom subnets and NAT environments.

---

## 🖥️ Supported Operating Systems

| Distribution | Supported Versions |
| :--- | :--- |
| **Debian** | 11, 12 |
| **Ubuntu** | 20.04, 22.04, 24.04 |
| **CentOS / Rocky / Alma** | 8, 9 |
| **Fedora / Arch Linux** | Latest |

---

## 🛠️ Installation & Usage

### Quick Install
Run the following command to download and start the interactive installer:

```bash
wget [https://github.com/waelisa/OpenVPN-Install/raw/refs/heads/main/openvpn-install.sh](https://github.com/waelisa/OpenVPN-Install/raw/refs/heads/main/openvpn-install.sh) -O openvpn-install.sh
chmod +x openvpn-install.sh
sudo ./openvpn-install.sh
