from unittest.mock import patch

from service_detection.engine import detect_service


def failing_detector(name, message):
    def wrapper(*args, **kwargs):
        raise RuntimeError(message)

    wrapper.__name__ = name
    return wrapper


def successful_https(*args, **kwargs):
    return {
        "service": "HTTPS",
        "product": "TestServer",
        "version": "1.0",
        "extra_info": None,
        "details": {}
    }


def test_detector_exception_isolated():

    original_ssh = failing_detector(
        "ssh_service_detection",
        "SSH detector failed"
    )

    successful_https.__name__ = "https_service_detection"

    with patch(
        "service_detection.engine.ssh_service_detection",
        new=original_ssh
    ), patch(
        "service_detection.engine.https_service_detection",
        new=successful_https
    ):

        result = detect_service("127.0.0.1", 8080, 2)

        assert result["service"] == "HTTPS"

    print("PASS: Detector exception did not stop engine")


def test_all_detectors_fail():

    detector_names = [
        "ssh_service_detection",
        "https_service_detection",
        "http_service_detection",
        "ftp_service_detection",
        "smtp_service_detection",
        "mysql_service_detection",
        "postgresql_service_detection",
        "dns_service_detection"
    ]

    patchers = []

    try:
        for name in detector_names:

            failing = failing_detector(
                name,
                f"{name} failed"
            )

            patcher = patch(
                f"service_detection.engine.{name}",
                new=failing
            )

            patcher.start()
            patchers.append(patcher)

        result = detect_service("127.0.0.1", 8080, 2)

        assert result["service"] is None
        assert result["details"]["error"] == (
            "No supported service protocol identified"
        )

    finally:
        for patcher in reversed(patchers):
            patcher.stop()

    print("PASS: All detector failures handled without crashing")

def successful_dns(*args, **kwargs):
    return {
        "service": "DNS",
        "product": None,
        "version": None,
        "extra_info": None,
        "details": {
            "udp": {"status": "RESPONDING"},
            "tcp": {"status": "NO RESPONSE"}
        }
    }


def test_dns_fallback():

    detector_names = [
        "ssh_service_detection",
        "https_service_detection",
        "http_service_detection",
        "ftp_service_detection",
        "smtp_service_detection",
        "mysql_service_detection",
        "postgresql_service_detection"
    ]

    patchers = []

    try:
        for name in detector_names:
            patcher = patch(
                f"service_detection.engine.{name}",
                new=failing_detector(name, f"{name} failed")
            )
            patcher.start()
            patchers.append(patcher)

        dns_function = successful_dns
        dns_function.__name__ = "dns_service_detection"

        with patch(
            "service_detection.engine.dns_service_detection",
            new=dns_function
        ):
            result = detect_service("127.0.0.1", 5353, 2)

        assert result["service"] == "DNS"

    finally:
        for patcher in reversed(patchers):
            patcher.stop()

    print("PASS: Engine falls back to DNS detection")

if __name__ == "__main__":

    test_detector_exception_isolated()
    test_all_detectors_fail()
    test_dns_fallback()

    print("\nAll engine tests passed.")
