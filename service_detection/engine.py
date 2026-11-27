
from service_detection.fingerprint import create_fingerprint

from service_detection.ssh import ssh_service_detection
from service_detection.https import https_service_detection
from service_detection.http import http_service_detection
from service_detection.ftp import ftp_service_detection
from service_detection.smtp import smtp_service_detection
from service_detection.mysql import mysql_service_detection
from service_detection.postgresql import postgresql_service_detection
from service_detection.dns import dns_service_detection


# Common ports are hints for probe ordering only.
# Every detector remains available as a fallback.
PORT_HINTS = {
    ssh_service_detection: {22, 2222},
    ftp_service_detection: {21, 2121},
    smtp_service_detection: {25, 465, 587, 2525},
    http_service_detection: {80, 8080, 8082},
    https_service_detection: {443, 8443},
    mysql_service_detection: {3306, 3307},
    postgresql_service_detection: {5432, 5433},
    dns_service_detection: {53, 5353},
}


def get_detector_order(port):

    detectors = [
        ssh_service_detection,
        https_service_detection,
        http_service_detection,
        ftp_service_detection,
        smtp_service_detection,
        mysql_service_detection,
        postgresql_service_detection,
        dns_service_detection,
    ]

    preferred = []

    for detector, common_ports in PORT_HINTS.items():

        if port in common_ports:
            preferred.append(detector)

    remaining = [
        detector
        for detector in detectors
        if detector not in preferred
    ]

    return preferred + remaining


def detect_service(target, port, timeout):

    probe_timeout = min(timeout, 0.5)

    detector_errors = {}

    for detector in get_detector_order(port):

        detector_name = detector.__name__

        try:

            if detector == dns_service_detection:

                result = detector(
                    target,
                    probe_timeout,
                    port
                )

            else:

                result = detector(
                    target,
                    port,
                    probe_timeout
                )

            if result.get("service") is not None:
                return result

            if result.get("details", {}).get("error"):
                detector_errors[detector_name] = (
                    result["details"]["error"]
                )

        except Exception as error:

            detector_errors[detector_name] = str(error)

    return create_fingerprint(
        service=None,
        details={
            "error": "No supported service protocol identified",
            "detector_errors": detector_errors
        }
    )
