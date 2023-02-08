from reconizer.scripts.bbot_helper import run_scan


def ssl_cert_entrypoint_internal(domain: str):
    kwargs = dict(modules=["sslcert"], output_modules=["json"])
    try:
        result = run_scan(domain, **kwargs)
        return dict(error=None, response=result)
    except Exception as err:
        return dict(error=err, response=None)
