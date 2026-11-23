def create_fingerprint(
    service,
    product=None,
    version=None,
    extra_info=None,
    details=None
):
    return {
        "service": service,
        "product": product,
        "version": version,
        "extra_info": extra_info,
        "details": details if details is not None else {}
    }
