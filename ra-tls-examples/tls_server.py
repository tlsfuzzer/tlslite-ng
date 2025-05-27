import socket
import tlslite
from tlslite.api import TLSConnection, X509, X509CertChain, parsePEMKey, HandshakeSettings
from tlslite.constants import CertificateType, ExtensionType
from tlslite.extensions import SupportedGroupsExtension, AttestationTokenExtension, CustomExtensionType
from tlslite.messages import CertificateEntry

# Load certificate and private key
cert = X509()
with open("serverCert.pem", "rb") as f:
    decoded = f.read().decode()
    #print(decoded)
    cert.parse(decoded)  # decode bytes to str for dePem()
    
print("---------------------")
cert_chain = X509CertChain([cert])
with open("serverKey.pem", "rb") as f:
    key_bytes = f.read()
    decoded = key_bytes.decode()
    private_key = parsePEMKey(decoded, private=True)


# Configure handshake settings for TLS 1.3
settings = HandshakeSettings()
settings.minVersion = (3, 4)  # TLS 1.3
settings.maxVersion = (3, 4)  # TLS 1.3

# Specify supported groups (elliptic curves)
supported_groups = SupportedGroupsExtension()
supported_groups.create([23, 24])  # secp256r1 (23), secp384r1 (24)
settings.extensions = [supported_groups]


# Read attestation token as binary
try:
    with open("sim_token.txt", "rb") as f:
        attestation_token = f.read()
        print(f"Attestation token size: {len(attestation_token)} bytes")
except FileNotFoundError:
    print("Error: sim_token.txt not found")
    exit(1)
except Exception as e:
    print(f"Error reading sim_token.txt: {e}")
    exit(1)
print(f"Attestation token loaded: {len(attestation_token) == 2700}")    


# Set up TCP socket
sock = socket.socket()
sock.bind(("127.0.0.1", 4433))
sock.listen(1)
print("Server listening on port 4433...")

while True:
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    tls_conn = TLSConnection(conn)

    try:
        # Perform TLS handshake with specified settings
        tls_conn.handshakeServer(None, cert_chain, private_key, settings=settings, attestation_token=attestation_token)
        print("TLS handshake complete!")

        # Communicate over TLS
        data = tls_conn.recv(1024)
        print("Received from client:", data.decode())
        tls_conn.sendall(b"Hello from server over TLS!")

    except Exception as e:
        print("TLS handshake failed:", e)
    finally:
        tls_conn.close()
