import socket
import ssl
import logging
import time
import random
import os
from pyroute2 import IPRoute
import threading
import select

# Logging configuration
logging.basicConfig(filename='vpn_client.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Constants for buffer size
BUFFER_SIZE = 4096
CERT_PATH = os.path.expanduser('~/.vpn/certs')  # Dynamically set path to certificates
CERT_FILE = os.path.join(CERT_PATH, 'client.crt')
KEY_FILE = os.path.join(CERT_PATH, 'client.key')
CA_FILE = os.path.join(CERT_PATH, 'ca.crt')

# Pool of client identities for spoofing
client_id_pool = ['client1', 'client2', 'client3']
current_client_id = random.choice(client_id_pool)

# Ensure certificate files exist
def ensure_certificates():
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE) or not os.path.exists(CA_FILE):
        logging.error("Certificate files missing. Ensure client.crt, client.key, and ca.crt are present.")
        raise FileNotFoundError("SSL certificates are missing for the client.")

# Create SSL context with enhanced security
def create_ssl_context(certfile, keyfile, cafile):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        context.load_verify_locations(cafile=cafile)
        context.verify_mode = ssl.CERT_REQUIRED  # Require server certificate verification
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable weak TLS versions
        context.set_ciphers('HIGH:!aNULL:!MD5:!RC4:!DSS')  # Use only strong ciphers
        logging.info("SSL context successfully created with enhanced security settings.")
        return context
    except ssl.SSLError as e:
        logging.error(f"Failed to create SSL context: {str(e)}")
        raise

# Create TUN interface
def create_tun_interface():
    try:
        ipr = IPRoute()
        tun_interface = ipr.link_lookup(ifname="vpn0")
        if not tun_interface:
            ipr.link_create(ifname="vpn0", kind="tun", mode="tun")
            tun_interface = ipr.link_lookup(ifname="vpn0")[0]
            ipr.addr("add", index=tun_interface, address="10.8.0.2", mask=24)
            ipr.link("set", index=tun_interface, state="up")
            logging.info("TUN interface 'vpn0' created and configured for client.")
        return tun_interface
    except Exception as e:
        logging.error(f"Error creating TUN interface: {str(e)}")
        raise

# Handle VPN traffic over the TUN interface
def handle_vpn_traffic(ssl_client_socket, tun_idx):
    ipr = IPRoute()
    try:
        while True:
            ready, _, _ = select.select([ssl_client_socket], [], [], 1)
            if ready:
                data = ssl_client_socket.recv(BUFFER_SIZE)
                if not data:
                    logging.info("No data received, closing connection.")
                    break
                # Write the incoming data to the TUN interface
                ipr.tc("send", ifindex=tun_idx, packet=data)
            else:
                continue

    except Exception as e:
        logging.error(f"Error handling VPN traffic: {str(e)}")
    finally:
        logging.info("VPN traffic handler terminated.")
        ssl_client_socket.close()

# Start VPN client
def start_vpn_client(server_address, port, certfile, keyfile, cafile):
    ensure_certificates()  # Ensure the required certificates are in place
    tun_idx = create_tun_interface()  # Set up the TUN interface
    context = create_ssl_context(certfile, keyfile, cafile)  # Create SSL context

    # Establish connection to the VPN server
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_client_socket = context.wrap_socket(client_socket, server_hostname=server_address)

        logging.info(f"Connecting to {server_address}:{port} as {current_client_id}")
        ssl_client_socket.connect((server_address, port))
        logging.info(f"Successfully connected to the VPN server as {current_client_id}")

        # Handle VPN traffic in a separate thread
        vpn_thread = threading.Thread(target=handle_vpn_traffic, args=(ssl_client_socket, tun_idx))
        vpn_thread.start()
        vpn_thread.join()

    except (socket.error, ssl.SSLError) as e:
        logging.error(f"Connection error: {str(e)}")
    finally:
        if 'client_socket' in locals():
            client_socket.close()

# Cycle through spoofed client identities, reconnecting at intervals
def cycle_client_connections(server_address, port, certfile, keyfile, cafile, interval=60):
    while True:
        global current_client_id
        current_client_id = random.choice(client_id_pool)  # Choose a new client identity
        start_vpn_client(server_address, port, certfile, keyfile, cafile)  # Connect using new identity
        logging.info(f"Disconnecting, waiting {interval} seconds before reconnecting as a new client.")
        time.sleep(interval)  # Wait and reconnect with a new identity

if __name__ == "__main__":
    server_address = 'vpn.example.com'  # Replace with actual server address
    port = 1194  # Replace with actual VPN port
    try:
        cycle_client_connections(server_address, port, CERT_FILE, KEY_FILE, CA_FILE)
    except Exception as e:
        logging.error(f"Fatal error in VPN client: {str(e)}")
