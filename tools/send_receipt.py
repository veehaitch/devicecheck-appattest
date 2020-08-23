#!/usr/bin/env python3
import requests
from requests import Response
from requests_toolbelt.utils.dump import dump_all
from base64 import b64encode

def send(receipt: bytes, token: str, verify: bool = True) -> Response:
    s = requests.Session()
    s.headers.update({
        "Authorization": token,
        "Content-Type": "base64"
    })
    s.verify = verify

    return s.post(
        'https://data-development.appattest.apple.com/v1/attestationData',
        data=b64encode(receipt)
    )


if __name__ == "__main__":
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt-path", "-r")
    parser.add_argument("--token", "-t")
    parser.add_argument("--no-verify-cert", "-n", action="store_true", default=False)
    args = parser.parse_args()

    r = send(
        receipt=Path(args.receipt_path).read_bytes(),
        token=args.token,
        verify=not args.no_verify_cert
    )
    print(dump_all(r).decode())

