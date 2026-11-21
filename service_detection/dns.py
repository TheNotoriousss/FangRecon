
import dns.message
import dns.query
import dns.rcode
import dns.flags
import dns.exception


def test_dns_protocol(query_function, query, target, timeout, port):

    result = {
        "status": "NO RESPONSE",
        "response_code": None,
        "error_type": None,
        "error": None
    }

    try:
        response = query_function(
            query,
            target,
            port=port,
            timeout=timeout
        )

        if not response.flags & dns.flags.QR:
            raise ValueError("Received packet is not a DNS response")

        if response.id != query.id:
            raise ValueError("DNS transaction ID mismatch")

        if response.question != query.question:
            raise ValueError("DNS question mismatch")

        result["status"] = "RESPONDING"
        result["response_code"] = dns.rcode.to_text(
            response.rcode()
        )

    except dns.exception.Timeout as e:
        result["status"] = "NO RESPONSE"
        result["error_type"] = "TIMEOUT"
        result["error"] = str(e)

    except ValueError as e:
        result["status"] = "ERROR"
        result["error_type"] = "INVALID_RESPONSE"
        result["error"] = str(e)

    except Exception as e:
        result["status"] = "ERROR"
        result["error_type"] = "OTHER"
        result["error"] = str(e)

    return result


def dns_service_detection(target, timeout=3, port=53):

    query = dns.message.make_query(
        "fangrecon-test.invalid",
        "A"
    )

    protocols = {
        "udp": dns.query.udp,
        "tcp": dns.query.tcp
    }

    result = {
        "service": "DNS"
    }

    for protocol, query_function in protocols.items():

        result[protocol] = test_dns_protocol(
            query_function,
            query,
            target,
            timeout,
            port
        )

    return result
