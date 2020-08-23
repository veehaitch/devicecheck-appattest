#!/usr/bin/env python3
import cryptography
from pathlib import Path
from base64 import urlsafe_b64encode

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

import json
import time

from typing import Dict

def b64(data: bytes) -> bytes:
    return urlsafe_b64encode(data).rstrip(b"=")

def j64(d: Dict) -> bytes:
    return b64(json.dumps(d, separators=(',', ':')).encode())

def sign_raw(data: bytes, privkey: EllipticCurvePrivateKey) -> bytes:
    signature_der = privkey.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    (r, s) = decode_dss_signature(signature_der)
    return b"".join([x.to_bytes(32, "big") for x in [r, s]])


def genjwt(privkey_pem: bytes, team_id: str, key_id: str) -> str:
    privkey = load_pem_private_key(privkey_pem, password=None, backend=default_backend())

    headers = j64({"alg": 'ES256', "kid": key_id})
    payload = j64({"iss": team_id, "iat": int(time.time())})

    data = headers + b"." + payload
    signature = sign_raw(data, privkey)

    return (data + b"." + b64(signature)).decode()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-key-pem_file", "-p")
    parser.add_argument("--team-id", "-t")
    parser.add_argument("--key-id", "-k")
    args = parser.parse_args()


    privkey_pem = Path(args.private_key_pem_file).read_bytes()
    jwt = genjwt(privkey_pem, args.team_id, args.key_id)
    print(jwt)

