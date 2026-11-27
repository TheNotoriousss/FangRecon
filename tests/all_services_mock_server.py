#!/usr/bin/env python3
"""
Unified FangRecon mock environment.

Starts all supported mock services together on 127.0.0.1.
Run from the FangRecon project root so test_cert.pem and test_key.pem
can be found for HTTPS.
"""

import argparse
import socket
import socketserver
import ssl
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


HOST = "127.0.0.1"
stop_event = threading.Event()


# ---------- Shared TCP server infrastructure ----------

class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        self.handle_client(self.request)

    def handle_client(self, conn):
        raise NotImplementedError


def start_tcp_service(name, port, handler_class):
    server = ThreadedTCPServer((HOST, port), handler_class)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[+] {name:<12} TCP listening on {HOST}:{port}")
    return server


# ---------- SSH ----------

class SSHHandler(TCPHandler):
    def handle_client(self, conn):
        conn.sendall(b"SSH-2.0-OpenSSH_9.9 Debian-1\r\n")
        # The fingerprinting probe only needs the server banner.
        try:
            conn.recv(1024)
        except (socket.timeout, OSError):
            pass


# ---------- HTTP / HTTPS ----------

class FangReconHTTPHandler(BaseHTTPRequestHandler):
    server_version = "FangRecon-Test"
    sys_version = "1.0"

    def do_GET(self):
        body = b"FangRecon unified mock service is running.\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, fmt, *args):
        print(f"[HTTP] {self.client_address[0]}:{self.client_address[1]} - {fmt % args}")


class ThreadedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_http_service(name, port, tls_context=None):
    server = ThreadedHTTPServer((HOST, port), FangReconHTTPHandler)

    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    protocol = "HTTPS" if tls_context else "HTTP"
    print(f"[+] {name:<12} {protocol} listening on {HOST}:{port}")
    return server


# ---------- FTP ----------

class FTPHandler(TCPHandler):
    def handle_client(self, conn):
        conn.sendall(b"220 ProFTPD 1.3.8 Server (FangRecon Test Server)\r\n")

        try:
            reader = conn.makefile("rb")
            while True:
                command = reader.readline()
                if not command:
                    break

                command_text = command.decode(errors="replace").strip()
                print(f"[FTP] {command_text}")

                upper = command_text.upper()
                if upper.startswith("FEAT"):
                    conn.sendall(
                        b"211-Features:\r\n"
                        b" UTF8\r\n"
                        b"211 End\r\n"
                    )
                elif upper.startswith("SYST"):
                    conn.sendall(b"215 UNIX Type: L8\r\n")
                elif upper.startswith("QUIT"):
                    conn.sendall(b"221 Goodbye\r\n")
                    break
                else:
                    conn.sendall(b"500 Command not recognized\r\n")
        except (socket.timeout, OSError):
            pass


# ---------- SMTP ----------

class SMTPHandler(TCPHandler):
    def handle_client(self, conn):
        conn.sendall(b"220 mail.fangrecon.local ESMTP Postfix 3.8.6\r\n")

        try:
            reader = conn.makefile("rb")
            while True:
                command = reader.readline()
                if not command:
                    break

                command_text = command.decode(errors="replace").strip()
                print(f"[SMTP] {command_text}")

                if command_text.upper().startswith(("EHLO", "HELO")):
                    conn.sendall(
                        b"250-mail.fangrecon.local\r\n"
                        b"250-PIPELINING\r\n"
                        b"250 SIZE 1024000\r\n"
                    )
                elif command_text.upper().startswith("QUIT"):
                    conn.sendall(b"221 Bye\r\n")
                    break
                else:
                    conn.sendall(b"500 Command not recognized\r\n")
        except (socket.timeout, OSError):
            pass


# ---------- MySQL ----------

MYSQL_SERVER_VERSION = b"8.0.36-fangrecon-test"


def create_mysql_greeting():
    connection_id = struct.pack("<I", 1)
    auth_part_1 = b"abcdefgh"
    auth_part_2 = b"ijklmnopqrst\x00"
    capability_flags = 0x00088200

    payload = (
        b"\x0a"
        + MYSQL_SERVER_VERSION
        + b"\x00"
        + connection_id
        + auth_part_1
        + b"\x00"
        + struct.pack("<H", capability_flags & 0xFFFF)
        + b"\x21"
        + struct.pack("<H", 2)
        + struct.pack("<H", capability_flags >> 16)
        + b"\x15"
        + b"\x00" * 10
        + auth_part_2
        + b"mysql_native_password\x00"
    )

    return len(payload).to_bytes(3, "little") + b"\x00" + payload


class MySQLHandler(TCPHandler):
    def handle_client(self, conn):
        conn.sendall(create_mysql_greeting())
        # Do not perform authentication; this is banner/protocol identification only.


# ---------- PostgreSQL ----------

def recv_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def send_parameter_status(conn, name, value):
    payload = name.encode() + b"\x00" + value.encode() + b"\x00"
    conn.sendall(b"S" + struct.pack("!I", len(payload) + 4) + payload)


class PostgreSQLHandler(TCPHandler):
    def handle_client(self, conn):
        # PostgreSQL SSLRequest: length=8, request code=80877103.
        request = recv_exact(conn, 8)
        if request is None:
            return

        length, request_code = struct.unpack("!II", request)
        if length != 8 or request_code != 80877103:
            return

        # Refuse TLS so the detector can continue with a plaintext StartupMessage.
        conn.sendall(b"N")

        header = recv_exact(conn, 4)
        if header is None:
            return

        message_length = struct.unpack("!I", header)[0]
        if message_length < 8 or message_length > 10000:
            return

        startup_data = recv_exact(conn, message_length - 4)
        if startup_data is None:
            return

        protocol_version = struct.unpack("!I", startup_data[:4])[0]
        print(f"[PostgreSQL] Startup protocol: {protocol_version}")

        # Identification-only mock response. No credentials are requested.
        conn.sendall(b"R" + struct.pack("!II", 8, 0))
        send_parameter_status(conn, "server_version", "16.4-fangrecon-mock")
        send_parameter_status(conn, "server_encoding", "UTF8")
        send_parameter_status(conn, "client_encoding", "UTF8")
        conn.sendall(b"Z" + struct.pack("!I", 5) + b"I")


# ---------- DNS (UDP and TCP on the same port) ----------

def build_dns_response(data):
    try:
        import dns.message
        import dns.rcode

        query = dns.message.from_wire(data)
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response.to_wire()
    except Exception:
        return None


class DNSTCPHandler(TCPHandler):
    def handle_client(self, conn):
        header = recv_exact(conn, 2)
        if header is None:
            return

        length = int.from_bytes(header, "big")
        query_data = recv_exact(conn, length)
        if query_data is None:
            return

        response = build_dns_response(query_data)
        if response:
            conn.sendall(len(response).to_bytes(2, "big") + response)


def start_dns_udp(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, port))
    sock.settimeout(0.5)

    def worker():
        while not stop_event.is_set():
            try:
                data, address = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            response = build_dns_response(data)
            if response:
                try:
                    sock.sendto(response, address)
                except OSError:
                    pass

        sock.close()

    threading.Thread(target=worker, daemon=True).start()
    print(f"[+] {'DNS':<12} UDP listening on {HOST}:{port}")
    return sock

def start_generic_udp(port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, port))
    sock.settimeout(0.5)

    def worker():

        while not stop_event.is_set():

            try:
                data, address = sock.recvfrom(1024)

            except socket.timeout:
                continue

            except OSError:
                break

            try:
                sock.sendto(
                    b"FANGRECON GENERIC UDP SERVICE",
                    address
                )

            except OSError:
                pass

        sock.close()

    threading.Thread(target=worker, daemon=True).start()

    print(f"[+] {'Unknown':<12} UDP listening on {HOST}:{port}")

    return sock
# ---------- Unknown TCP service ----------

class UnknownHandler(TCPHandler):
    def handle_client(self, conn):
        conn.sendall(b"FANGRECON UNKNOWN SERVICE\r\n")
        try:
            conn.recv(1024)
        except (socket.timeout, OSError):
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Start all FangRecon mock services together."
    )
    parser.add_argument("--cert", default="test_cert.pem")
    parser.add_argument("--key", default="test_key.pem")
    args = parser.parse_args()

    servers = []
    udp_socket = None
    generic_udp_socket = None

    try:
        # Load certificate before starting any listener, so HTTPS failure is clear.
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(args.cert, args.key)

        servers.append(start_tcp_service("SSH", 2222, SSHHandler))
        servers.append(start_http_service("HTTP", 8082))
        servers.append(start_http_service("HTTPS", 8443, tls_context))
        servers.append(start_tcp_service("FTP", 2121, FTPHandler))
        servers.append(start_tcp_service("SMTP", 2525, SMTPHandler))
        servers.append(start_tcp_service("MySQL", 3307, MySQLHandler))
        servers.append(start_tcp_service("PostgreSQL", 5433, PostgreSQLHandler))
        servers.append(start_tcp_service("DNS-TCP", 5353, DNSTCPHandler))
        udp_socket = start_dns_udp(5353)
        generic_udp_socket = start_generic_udp(9999)
        servers.append(start_tcp_service("Unknown", 9999, UnknownHandler))

        print("\n[+] All FangRecon mock services are running.")
        print("[+] Press Ctrl+C to stop all services.\n")

        while True:
            stop_event.wait(1)

    except KeyboardInterrupt:
        print("\n[!] Stopping all mock services...")

    finally:
        stop_event.set()
        if generic_udp_socket is not None:
            generic_udp_socket.close()
        if udp_socket is not None:
            udp_socket.close()

        for server in servers:
            server.shutdown()
            server.server_close()

        print("[+] All mock services stopped.")


if __name__ == "__main__":
    main()
