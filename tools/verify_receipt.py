#!/usr/bin/env python3

from OpenSSL import crypto
from OpenSSL._util import (
    ffi as _ffi,
    lib as _lib,
)

APPLE_ROOT_PEM = b'-----BEGIN CERTIFICATE-----\nMIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9v\ndCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UE\nCgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2\nWjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmlj\nYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqG\nSM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxE\ntX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNC\nMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P\nAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3m\neoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkL\nF1vLUagM6BgD56KyKA==\n-----END CERTIFICATE-----'
root = ca_ssl = crypto.load_certificate(crypto.FILETYPE_PEM, APPLE_ROOT_PEM)
store = crypto.X509Store()
store.add_cert(root)

def verify(receipt: bytes):
    p7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, receipt)

    bio_out = crypto._new_mem_buf()
    res = _lib.PKCS7_verify(p7._pkcs7, _ffi.NULL, store._store, _ffi.NULL, bio_out, 0)

    if res == 1:
        databytes = crypto._bio_to_string(bio_out)
        print(databytes)
    else:
        errno = _lib.ERR_get_error()
        errstrlib = _ffi.string(_lib.ERR_lib_error_string(errno)).decode()
        errstrfunc = _ffi.string(_lib.ERR_func_error_string(errno)).decode()
        errstrreason = _ffi.string(_lib.ERR_reason_error_string(errno)).decode()

        print(f"errno:        {errno}")
        print(f"errstrlib:    {errstrlib}")
        print(f"errstrfunc:   {errstrfunc}")
        print(f"errstrreason: {errstrreason}")

if __name__ == "__main__":
    import argparse, pathlib
    parser = argparse.ArgumentParser()
    parser.add_argument("receiptfile")
    args = parser.parse_args()

    receipt = pathlib.Path(args.receiptfile).read_bytes()
    verify(receipt)

