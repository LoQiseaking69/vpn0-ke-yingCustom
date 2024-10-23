import socket
import ssl
import os
import logging
import random
from pyroute2 import IPRoute
import signal
import threading
import select

# Logging configuration
logging.basicConfig(filename='vpn_server.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Constants
BUFFER_SIZE = 4096
VPN_INTERFACE_NAME = "vpn0"
VPN_SERVER_IP = "10.8.0.1/24"
VPN_PORT = 1194
MAX_CLIENTS = 10  # Maximum number of simultaneous clients
CERT_PATH = os.path.expanduser('~/.vpn/certs')  # Dynamic, based on home directory
CERT_FILE = os.path.join(CERT_PATH, 'server.crt')
KEY_FILE = os.path.join(CERT_PATH, 'server.key')
CA_FILE = os.path.join(CERT_PATH, 'ca.crt')

# Dynamic IP pool for clients
ip_pool = ["10.8.0.2", "10.8.0.3", "10.8.0.4"]
assigned_ips = set()

# Graceful shutdown handler
def handle_sigterm(signum, frame):
    logging.info("Received termination signal. Shutting down VPN server.")
    os._exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)

# Create TUN interface
def create_tun_interface():
    try:
        ipr = IPRoute()
        tun_interface = ipr.link_lookup(ifname=VPN_INTERFACE_NAME)
        if not tun_interface:
            ipr.link_create(ifname=VPN_INTERFACE_NAME, kind="tun", mode="tun")
            tun_interface = ipr.link_lookup(ifname=VPN_INTERFACE_NAME)[0]
            ipr.addr("add", index=tun_interface, address=VPN_SERVER_IP.split('/')[0], mask=int(VPN_SERVER_IP.split('/')[1]))
            ipr.link("set", index=tun_interface, state="up")
            logging.info(f"TUN interface '{VPN_INTERFACE_NAME}' created with IP {VPN_SERVER_IP}")
        return tun_interface
    except Exception as e:
        logging.error(f"Error creating TUN interface: {str(e)}")
        raise

# SSL context creation for the server
def create_ssl_context(certfile, keyfile, cafile):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        context.load_verify_locations(cafile=cafile)
        context.verify_mode = ssl.CERT_REQUIRED  # Enforce client certificate verification
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable old and insecure TLS versions
        context.set_ciphers('HIGH:!aNULL:!MD5:!RC4:!DSS')  # Use only strong ciphers
        return context
    except ssl.SSLError as e:
        logging.error(f"Error creating SSL context: {str(e)}")
        raise

# Assign a dynamic IP from the pool
def assign_ip():
    available_ips = list(set(ip_pool) - assigned_ips)
    if available_ips:
        new_ip = random.choice(available_ips)
        assigned_ips.add(new_ip)
        return new_ip
    logging.error("No available IPs to assign")
    return None

# Release an IP back to the pool
def release_ip(ip):
    if ip in assigned_ips:
        assigned_ips.remove(ip)

# Handle VPN traffic over the TUN interface
def handle_vpn_traffic(ssl_client_socket, tun_idx):
    client_ip = assign_ip()
    if not client_ip:
        logging.error("No available IP for new connection")
        ssl_client_socket.close()
        return

    ipr = IPRoute()
    try:
        ipr.addr("add", index=tun_idx, address=client_ip, mask=24)  # Assign dynamic IP from pool
        logging.info(f"Assigned IP {client_ip} to the client")

        while True:
            ready, _, _ = select.select([ssl_client_socket], [], [], 1)
            if ready:
                data = ssl_client_socket.recv(BUFFER_SIZE)
                if not data:
                    logging.info("Client disconnected.")
                    break
                # Write the incoming data to the TUN interface
                ipr.tc("send", ifindex=tun_idx, packet=data)
            else:
                continue

    except Exception as e:
        logging.error(f"Error handling VPN traffic: {str(e)}")
    finally:
        release_ip(client_ip)
        logging.info(f"Released IP {client_ip}")
        ssl_client_socket.close()

# Start the VPN server
def start_vpn_server(host='0.0.0.0', port=VPN_PORT):
    tun_idx = create_tun_interface()
    context = create_ssl_context(CERT_FILE, KEY_FILE, CA_FILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(MAX_CLIENTS)
        logging.info(f"VPN Server started on {host}:{port}, waiting for clients...")

        while True:
            try:
                client_socket, client_address = server_socket.accept()
                logging.info(f"Connection from {client_address}")
                ssl_client_socket = context.wrap_socket(client_socket, server_side=True)

                logging.info(f"SSL handshake complete with {client_address}")
                threading.Thread(target=handle_vpn_traffic, args=(ssl_client_socket, tun_idx)).start()

            except ssl.SSLError as ssl_error:
                logging.error(f"SSL error occurred: {str(ssl_error)}")
            except Exception as e:
                logging.error(f"Unexpected server error: {str(e)}")
            finally:
                if 'client_socket' in locals():
                    client_socket.close()

if __name__ == "__main__":
    start_vpn_server()
