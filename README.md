 # Personal VPN  Server and Client with Dynamic IP Shifting

This project provides a fully implemented Python-based VPN solution using SSL/TLS encryption, dynamic IP shifting, and TUN interfaces for routing traffic. The VPN server and client scripts are tightly integrated with robust logging, client certificate authentication, and dynamic IP assignment. This VPN solution is designed for personal use, supporting multiple spoofed clients and dynamic IP management.

## Features

- **SSL/TLS Encryption**: Secure communication between the VPN client and server using SSL/TLS certificates.
- **Client Authentication**: Enforces client certificate validation, ensuring that only authorized clients can connect.
- **TUN Interface**: The server and client use TUN interfaces to route traffic over the VPN, allowing seamless data transmission.
- **Dynamic IP Assignment**: The server dynamically assigns IP addresses to clients from a predefined pool, simulating multiple client connections with dynamic IP shifts.
- **Systemd Integration**: The VPN server can be managed as a systemd service, allowing easy start, stop, and restart commands.
- **Logging**: Activity is logged on both the server and client sides for easier monitoring and troubleshooting.
- **Traffic Routing and NAT**: The server can route traffic from the VPN clients to external networks using NAT.

## Prerequisites

- **Python 3.x** installed on both server and client machines
- `pyOpenSSL`, `cryptography`, and `pyroute2` Python libraries for SSL/TLS and TUN interface management
- **Easy-RSA** for certificate generation
- **TUN/TAP interfaces** enabled on both server and client machines
- **UFW (Uncomplicated Firewall)** and **iptables-persistent** for securing and managing network traffic

### Installing Dependencies

You can install the required dependencies by running the following commands:

```bash
sudo apt-get update
sudo apt-get install -y python3-pip easy-rsa openvpn ufw iptables-persistent
pip3 install pyOpenSSL cryptography pyroute2
```

### Generating Certificates

The VPN solution uses SSL certificates for secure communication. You need a Certificate Authority (CA) to issue certificates for the server and clients. Follow these steps to generate them:

1. **Install Easy-RSA**:
   ```bash
   sudo apt-get install easy-rsa
   ```

2. **Initialize Easy-RSA and Build CA**:
   ```bash
   make-cadir ~/easy-rsa
   cd ~/easy-rsa
   ./easyrsa init-pki
   ./easyrsa build-ca nopass
   ```

3. **Generate Server Certificates**:
   ```bash
   ./easyrsa gen-req server nopass
   ./easyrsa sign-req server server
   ```

4. **Generate Client Certificates**:
   ```bash
   ./easyrsa gen-req client nopass
   ./easyrsa sign-req client client
   ```

5. **Distribute Certificates**:
   - **Server**: Move `server.crt`, `server.key`, and `ca.crt` to the VPN server machine.
   - **Client**: Move `client.crt`, `client.key`, and `ca.crt` to the VPN client machine.

## VPN Setup Script

Use the **automated setup script** (`setup.sh`) to streamline the installation and configuration of the VPN server:

1. **Make the script executable**:
   ```bash
   chmod +x setup.sh
   ```

2. **Run the setup script**:
   ```bash
   sudo ./setup.sh
   ```

This script installs necessary dependencies, generates SSL certificates, configures IP forwarding and NAT, and sets up firewall rules with UFW. Additionally, it creates a systemd service to manage the VPN server as a background process.

## Running the VPN Server

1. **Ensure the certificates** (`server.crt`, `server.key`, and `ca.crt`) are in the directory where the `vpn_server.py` script is located.
2. **Start the VPN server** (as a systemd service created by the setup script):
   ```bash
   sudo systemctl start vpnserver.service
   ```

The server listens for incoming client connections on port `1194` and handles dynamic IP assignment, SSL handshakes, and traffic routing via a TUN interface (`vpn0`).

## Running the VPN Client

1. **Ensure the certificates** (`client.crt`, `client.key`, and `ca.crt`) are in the directory where the `vpn_client.py` script is located.
2. **Run the VPN client**:
   ```bash
   python vpn_client.py
   ```

The client will create a TUN interface (`vpn0`) and connect to the VPN server, securely routing traffic through the established VPN tunnel.

## Traffic Routing and NAT

To enable traffic routing from the VPN clients to external networks, configure NAT on the VPN server:

1. **Enable IP forwarding**:
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   ```

2. **Set up NAT** (replace `eth0` with your actual network interface):
   ```bash
   sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
   ```

These configurations are automatically applied by the setup script, ensuring that VPN clients can access external networks.

## Logging

- Logs are created in the files `vpn_server.log` and `vpn_client.log` for easier monitoring of activity and troubleshooting.
- Detailed logs ensure that issues with SSL handshakes, traffic handling, and client connections can be identified quickly.

## Security Notes

- Only trusted clients with valid certificates can connect to the VPN server, ensuring a secure and authenticated connection.
- Ensure firewall rules are in place to protect the VPN server from unauthorized access.
- The setup script automatically configures UFW to allow VPN traffic while ensuring SSH access remains open.

## License

Unlicense license.

## Acknowledgements

- Uses Python libraries such as `pyOpenSSL`, `cryptography`, and `pyroute2`.
- Certificate generation via Easy-RSA.
