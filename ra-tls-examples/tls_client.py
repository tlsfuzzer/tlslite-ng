import socket
import tlslite
print(tlslite.__file__)
from tlslite.api import TLSConnection, HandshakeSettings
from tlslite.constants import ExtensionType, HandshakeType
from tlslite.extensions import SupportedGroupsExtension, AttestationTokenExtension, CustomExtensionType
from tlslite.messages import Certificate

DEBUG_ENABLED = False

def print_ServerHello_extensions(tls_conn):
    # Read ServerHello extensions
    server_hello_extensions = tls_conn._server_hello.extensions
    print("ServerHello Extensions:")
    if server_hello_extensions:
        for ext in server_hello_extensions:
            ext_type = ext.extType
            ext_name = getattr(ExtensionType, str(ext_type), ext_type) if isinstance(ext_type, int) else ext_type
            print(f"  Type: {ext_name}, Data: {ext}")
    else:
        print("  None")
        
def print_Certificate_msg(tls_conn):
    print("\nCertificate Message:")
    server_cert_chain = tls_conn.session.serverCertChain
    if server_cert_chain and server_cert_chain.x509List:
        for i, cert in enumerate(server_cert_chain.x509List):
            print(f"Certificate {i}:")
            print(f"  Length: {len(cert.bytes)} bytes")
    else:
        print("  No certificates found")        

# Configure handshake settings for TLS 1.3
settings = HandshakeSettings()
settings.minVersion = (3, 4)  # TLS 1.3
settings.maxVersion = (3, 4)  # TLS 1.3

# Connect to server
sock = socket.create_connection(("127.0.0.1", 4433))
tls_conn = TLSConnection(sock)

try:
    # Perform TLS handshake
    tls_conn.handshakeClientCert(settings=settings)
    print("TLS handshake complete!")

    if DEBUG_ENABLED : print_ServerHello_extensions(tls_conn)

    if DEBUG_ENABLED : print_Certificate_msg(tls_conn)
        

    # Read AttestationTokenExtension from Certificate message
    if hasattr(tls_conn, '_server_certificate') and tls_conn._server_certificate:
        cert_entry = tls_conn._server_certificate.certificate_list[0]
        for ext in cert_entry.extensions:
            if ext.extType == 65280:  # AttestationTokenExtension
                if DEBUG_ENABLED : print(f"AttestationTokenExtension found: {len(ext.token)} bytes")
                with open("received_token.bin", "wb") as f:
                    f.write(ext.token)
                if DEBUG_ENABLED : print("Saved AttestationTokenExtension to received_token.bin")
    else:
        if DEBUG_ENABLED : print("  No AttestationTokenExtension found (Certificate message not stored)")
        
        
    # Communicate over TLS
    tls_conn.sendall(b"Hello from client!")
    response = tls_conn.recv(1024)
    print("\nReceived from server:", response.decode())

except Exception as e:
    print("TLS handshake failed:", e)
finally:
    tls_conn.close()