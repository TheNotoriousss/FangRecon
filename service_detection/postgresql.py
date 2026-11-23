import socket
import ssl
import struct

from service_detection.fingerprint import create_fingerprint


def parse_backend_key_data(payload):

    # BackendKeyData contains:
    # 4 bytes: process ID
    # 4 bytes: secret key

    if len(payload) != 8:
        return False

    return True


def recv_exact(sock, size):

    data = b""

    while len(data) < size:

        chunk = sock.recv(size - len(data))

        if not chunk:
            return None

        data += chunk

    return data


def build_startup_message():

    parameters = (
        b"user\x00fangrecon\x00"
        b"database\x00postgres\x00"
        b"\x00"
    )

    protocol_version = struct.pack("!I", 196608)

    payload = protocol_version + parameters

    return struct.pack("!I", len(payload) + 4) + payload



def parse_error_response(payload):

    errors = {}
    position = 0

    if not payload:
        return None

    while position < len(payload):

        # Final zero byte marks the end of the message.
        if payload[position] == 0:

            if position != len(payload) - 1:
                return None

            return errors

        # Every field needs an identifier and a value.
        if position + 1 >= len(payload):
            return None

        field_code = payload[position:position + 1]

        if not (32 <= field_code[0] <= 126):
            return None

        position += 1

        value_end = payload.find(b"\x00", position)

        if value_end == -1:
            return None

        value = payload[position:value_end].decode(
            "utf-8",
            errors="replace"
        )

        key = field_code.decode("ascii")
        errors[key] = value

        position = value_end + 1

    return None


def parse_notice_response(payload):

    if not payload:
        return None

    notice = {}
    position = 0

    while position < len(payload):

        if payload[position] == 0:

            if position != len(payload) - 1:
                return None

            return notice

        if position + 1 >= len(payload):
            return None

        field_code = payload[position:position + 1]

        if not (32 <= field_code[0] <= 126):
            return None

        position += 1

        value_end = payload.find(b"\x00", position)

        if value_end == -1:
            return None

        try:
            value = payload[position:value_end].decode("utf-8")
        except UnicodeDecodeError:
            return None

        key = field_code.decode("ascii")
        notice[key] = value

        position = value_end + 1

    return None


def parse_authentication(payload, details):

    if len(payload) < 4:
        return False, False

    auth_code = struct.unpack("!I", payload[:4])[0]
    auth_data = payload[4:]

    # AuthenticationOk
    if auth_code == 0:

        if auth_data:
            return False, False

        details["authentication"] = "AuthenticationOk"
        return False, True

    # These methods must contain only the 4-byte method code.
    simple_methods = {
        2: "KerberosV5",
        3: "CleartextPassword",
        6: "SCMCredential",
        7: "GSS",
        9: "SSPI"
    }

    if auth_code in simple_methods:

        if auth_data:
            return False, False

        details["authentication"] = simple_methods[auth_code]
        return True, True

    # MD5 authentication requires exactly 4 bytes of salt.
    elif auth_code == 5:

        if len(auth_data) != 4:
            return False, False

        details["authentication"] = "MD5Password"
        return True, True

    # SASL authentication requires a properly terminated
    # list of non-empty mechanism names.
    elif auth_code == 10:

        if not auth_data.endswith(b"\x00"):
            return False, False

        mechanisms = auth_data.split(b"\x00")

        if (
            len(mechanisms) < 3
            or mechanisms[-2] != b""
            or mechanisms[-1] != b""
            or any(not item for item in mechanisms[:-2])
        ):
            return False, False

        try:
            mechanisms = [
                item.decode("ascii")
                for item in mechanisms[:-2]
            ]
        except UnicodeDecodeError:
            return False, False

        details["authentication"] = mechanisms
        return True, True

    # GSS continuation.
    elif auth_code == 8:

        details["authentication"] = "GSSContinue"
        return True, True

    # SASL continuation and final messages require data.
    elif auth_code == 11:

        if not auth_data:
            return False, False

        details["authentication"] = "SASLContinue"
        return True, True

    elif auth_code == 12:

        if not auth_data:
            return False, False

        details["authentication"] = "SASLFinal"
        return True, True

    return False, False



def read_server_responses(sock, details):

    version = None
    protocol_confirmed = False

    while True:

        message_type = recv_exact(sock, 1)

        if message_type is None:
            details["error"] = "Connection closed unexpectedly"
            break

        length_data = recv_exact(sock, 4)

        if length_data is None:
            details["error"] = "Incomplete message length"
            break

        message_length = struct.unpack("!I", length_data)[0]

        if message_length < 4 or message_length > 10000:
            details["error"] = "Invalid PostgreSQL message length"
            break

        payload = recv_exact(sock, message_length - 4)

        if payload is None:
            details["error"] = "Incomplete PostgreSQL message"
            break

        if message_type == b"R":

            stop, valid = parse_authentication(
                payload,
                details
            )

            if not valid:
                details["error"] = "Malformed PostgreSQL authentication message"
                break

            protocol_confirmed = True

            if stop:
                break

        elif message_type == b"S":

            try:

                parts = payload.split(b"\x00")

                if len(parts) != 3 or parts[-1] != b"":
                    raise ValueError

                name = parts[0].decode("utf-8")
                value = parts[1].decode("utf-8")

                if not name or name in details["server_parameters"]:
                    raise ValueError

                protocol_confirmed = True

                details["server_parameters"][name] = value

                if name == "server_version":
                    version = value

            except (ValueError, UnicodeDecodeError):

                details["error"] = "Malformed ParameterStatus"
                break

        elif message_type == b"E":

            error_response = parse_error_response(payload)

            if error_response is None:
                details["error"] = "Malformed ErrorResponse"
                break

            protocol_confirmed = True

            details["error_response"] = error_response
            details["error"] = "PostgreSQL ErrorResponse"
            break

        elif message_type == b"Z":

            if len(payload) != 1 or payload not in (b"I", b"T", b"E"):
                details["error"] = "Malformed ReadyForQuery"
                break

            protocol_confirmed = True
            details["ready_for_query"] = payload.decode("ascii")
            break
        elif message_type == b"K":

            if not parse_backend_key_data(payload):
                details["error"] = "Malformed BackendKeyData"
                break

            protocol_confirmed = True

        elif message_type == b"N":

            notice = parse_notice_response(payload)

            if notice is None:
                details["error"] = "Malformed NoticeResponse"
                break

            protocol_confirmed = True
            details.setdefault("notices", []).append(notice)
        else:

            details["error"] = "Unexpected PostgreSQL message type"
            break

    return version, protocol_confirmed



def postgresql_service_detection(target, port, timeout):

    details = {
        "ssl_supported": None,
        "ssl_response": None,
        "tls_version": None,
        "authentication": None,
        "server_parameters": {},
        "error": None
    }

    version = None
    protocol_confirmed = False

    try:

        with socket.create_connection(
            (target, port),
            timeout=timeout
        ) as raw_sock:

            raw_sock.settimeout(timeout)

            # Request PostgreSQL SSL negotiation

            ssl_request = struct.pack("!II", 8, 80877103)

            raw_sock.sendall(ssl_request)

            response = recv_exact(raw_sock, 1)

            if response == b"S":

                details["ssl_supported"] = True
                details["ssl_response"] = "S"

                # Establish TLS

                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with context.wrap_socket(
                    raw_sock,
                    server_hostname=target
                ) as sock:

                    details["tls_version"] = sock.version()

                    # Send StartupMessage over TLS

                    sock.sendall(build_startup_message())

                    # Read server responses

                    version, protocol_confirmed = read_server_responses(sock, details)

            elif response == b"N":

                details["ssl_supported"] = False
                details["ssl_response"] = "N"

                # Continue without TLS

                raw_sock.sendall(build_startup_message())

                # Read server responses

                version, protocol_confirmed = read_server_responses(raw_sock, details)

            elif response is None:

                details["error"] = "Connection closed without SSL response"

            else:

                details["ssl_response"] = response.hex()
                details["error"] = "Unexpected PostgreSQL SSL response"

    except ssl.SSLError as e:

        details["error"] = f"TLS error: {e}"

    except socket.timeout:

        details["error"] = "PostgreSQL response timed out"

    except OSError as e:

        details["error"] = str(e)

    return create_fingerprint(
        service="PostgreSQL" if protocol_confirmed else None,
        product="PostgreSQL" if protocol_confirmed else None,
        version=version,
        details=details
    )
