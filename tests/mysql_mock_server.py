import socket
import struct


HOST = "127.0.0.1"
PORT = 3307

SERVER_VERSION = b"8.0.36-fangrecon-test"



def create_mysql_greeting():

    connection_id = struct.pack("<I", 1)

    auth_plugin_data_part_1 = b"abcdefgh"
    auth_plugin_data_part_2 = b"ijklmnopqrst\x00"

    # CLIENT_PROTOCOL_41
    # CLIENT_SECURE_CONNECTION
    # CLIENT_PLUGIN_AUTH
    capability_flags = 0x00088200

    payload = (
        b"\x0a"
        + SERVER_VERSION
        + b"\x00"
        + connection_id
        + auth_plugin_data_part_1
        + b"\x00"
        + struct.pack("<H", capability_flags & 0xFFFF)
        + b"\x21"
        + struct.pack("<H", 2)
        + struct.pack("<H", capability_flags >> 16)
        + b"\x15"
        + b"\x00" * 10
        + auth_plugin_data_part_2
        + b"mysql_native_password\x00"
    )

    packet_length = len(payload).to_bytes(3, "little")
    sequence_id = b"\x00"

    return packet_length + sequence_id + payload


def start_server():

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind((HOST, PORT))
    server.listen(5)

    print(f"[+] Mock MySQL server listening on {HOST}:{PORT}")

    try:

        while True:

            client, address = server.accept()

            print(f"[+] Connection received from {address}")

            with client:

                greeting = create_mysql_greeting()
                client.sendall(greeting)

    except KeyboardInterrupt:
        print("\n[!] Mock server stopped")

    finally:
        server.close()


if __name__ == "__main__":
    start_server()
