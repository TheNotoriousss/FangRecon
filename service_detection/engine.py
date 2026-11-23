
from service_detection.fingerprint import create_fingerprint

from service_detection.ssh import ssh_service_detection
from service_detection.https import https_service_detection
from service_detection.http import http_service_detection
from service_detection.ftp import ftp_service_detection
from service_detection.smtp import smtp_service_detection
from service_detection.mysql import mysql_service_detection
from service_detection.postgresql import postgresql_service_detection
from service_detection.dns import dns_service_detection


def detect_service(target, port, timeout):

    probe_timeout = min(timeout, 0.5)

    detectors = [
        ssh_service_detection,
        https_service_detection,
        http_service_detection,
        ftp_service_detection,
        smtp_service_detection,
        mysql_service_detection,
        postgresql_service_detection,
    ]

    detector_errors = {}

    for detector in detectors:

        detector_name = detector.__name__

        try:
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

    # DNS uses a different function signature.
    try:
        result = dns_service_detection(
            target,
            probe_timeout,
            port
        )

        if result.get("service") is not None:
            return result

        if result.get("details"):
            detector_errors["dns_service_detection"] = (
                result["details"]
            )

    except Exception as error:
        detector_errors["dns_service_detection"] = str(error)

    return create_fingerprint(
        service=None,
        details={
            "error": "No supported service protocol identified",
            "detector_errors": detector_errors
        }
    )
