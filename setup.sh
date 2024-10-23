#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root." >&2
  exit 1
fi

# Get the public IP of the server dynamically
SERVER_IP=$(curl -s http://checkip.amazonaws.com)

# Define default VPN configurations
VPN_PORT="1194"  # Default VPN port
VPN_NETWORK="10.8.0.0/24"  # Subnet for VPN clients
EXT_IF=$(ip -o -4 route show to default | awk '{print $5}')  # Automatically detect external network interface
EASY_RSA_DIR=~/easy-rsa  # Easy-RSA installation directory
VPN_CERTS_DIR=~/vpn_certs  # Directory to store VPN certificates
PYTHON_VPN_SERVER_PATH=~/vpn_server.py  # Path to the Python VPN server script

echo "Starting VPN setup..."

# 1. Install required packages
echo "Installing dependencies..."
sudo apt-get update -y
sudo apt-get install -y python3-pip easy-rsa openvpn ufw iptables-persistent curl

# Install Python dependencies for the VPN scripts
pip3 install pyOpenSSL cryptography pyroute2

# 2. SSL/TLS Certificate setup using Easy-RSA
echo "Setting up Easy-RSA..."
if [ ! -d "$EASY_RSA_DIR" ]; then
  make-cadir $EASY_RSA_DIR
fi
cd $EASY_RSA_DIR
./easyrsa init-pki
./easyrsa build-ca nopass

# Generate server certificate
./easyrsa gen-req server nopass
./easyrsa sign-req server server

# Generate client certificate
./easyrsa gen-req client nopass
./easyrsa sign-req client client

# Move certificates to appropriate directories
echo "Moving certificates to $VPN_CERTS_DIR..."
mkdir -p $VPN_CERTS_DIR
cp pki/private/server.key $VPN_CERTS_DIR/
cp pki/issued/server.crt $VPN_CERTS_DIR/
cp pki/ca.crt $VPN_CERTS_DIR/
cp pki/private/client.key $VPN_CERTS_DIR/
cp pki/issued/client.crt $VPN_CERTS_DIR/

# 3. Configure IP forwarding and NAT (for internet access over VPN)
echo "Configuring IP forwarding and NAT..."
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
if ! grep -q "net.ipv4.ip_forward = 1" /etc/sysctl.conf; then
  echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
fi

# Set up NAT on the external interface
sudo iptables -t nat -A POSTROUTING -s $VPN_NETWORK -o $EXT_IF -j MASQUERADE
# Save iptables rule for persistence
sudo iptables-save | sudo tee /etc/iptables/rules.v4
sudo systemctl enable netfilter-persistent
sudo netfilter-persistent save

# 4. Harden VPN server with UFW (firewall)
echo "Configuring UFW firewall..."
sudo ufw allow $VPN_PORT/tcp
sudo ufw allow $VPN_PORT/udp
sudo ufw allow OpenSSH
sudo ufw enable
sudo ufw reload

# 5. Optimize server for high-performance VPN
echo "Optimizing server performance..."

# Increase the buffer sizes for networking to handle more traffic
if ! grep -q "net.core.rmem_max" /etc/sysctl.conf; then
  echo "net.core.rmem_max=26214400" | sudo tee -a /etc/sysctl.conf
fi
if ! grep -q "net.core.wmem_max" /etc/sysctl.conf; then
  echo "net.core.wmem_max=26214400" | sudo tee -a /etc/sysctl.conf
fi
sudo sysctl -p

# Configure TCP optimization for better performance
sudo bash -c 'cat >> /etc/sysctl.conf << EOF
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_rmem = 4096 87380 4194304
net.ipv4.tcp_wmem = 4096 87380 4194304
EOF'
sudo sysctl -p

# 6. Create VPN start/stop services dynamically
echo "Creating VPN server start/stop services..."

# Dynamically get the Python VPN server script path
if [ ! -f "$PYTHON_VPN_SERVER_PATH" ]; then
  read -p "Enter the absolute path to the Python VPN server script (e.g., /home/username/vpn_server.py): " PYTHON_VPN_SERVER_PATH
fi

sudo bash -c "cat > /etc/systemd/system/vpnserver.service << EOF
[Unit]
Description=VPN Server using Python
After=network.target

[Service]
ExecStart=/usr/bin/python3 $PYTHON_VPN_SERVER_PATH
WorkingDirectory=$(dirname $PYTHON_VPN_SERVER_PATH)
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF"

sudo systemctl daemon-reload
sudo systemctl enable vpnserver.service

# 7. Display client connection details
echo -e "\n*** VPN setup completed successfully! ***"
echo "Your VPN server is now ready to use with dynamic IP shifting."
echo "Client certificates have been saved in: $VPN_CERTS_DIR"
echo "You can start the VPN server with: sudo systemctl start vpnserver.service"
echo "Connect your VPN clients using the certificates located in $VPN_CERTS_DIR."
echo "VPN Server IP: $SERVER_IP, Port: $VPN_PORT"
