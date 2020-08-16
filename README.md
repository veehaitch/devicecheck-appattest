# Apple App Attest Validation

Proof of concept for validating the authenticity of Apple App Attest statements, written in Kotlin.

The implementation follows the steps outlined in the article ["Validating Apps That Connect to Your Server"](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server) at Apple Developer.

It relies on:

- [Jackson](https://github.com/FasterXML/jackson-dataformats-binary/tree/master/cbor) for parsing the CBOR-encoded `apple-attest` attestation statement.
- [Bouncy Castle](https://www.bouncycastle.org/) for ASN.1 parsing of Apple's X509 extension containing the _nonce_.
- [WebAuth4J](https://github.com/webauthn4j/webauthn4j) for parsing the WebAuthn _authenticator data_ of the `apple-attest` attestation statement. 

## Usage Example

```kotlin
// Create an Attestation instance specific to a given iOS app and development team
val attestation = Attestation(
    appleTeamIdentifier = "6MURL8TA57",
    appCfBundleIdentifier = "de.vincent-haupert.AppleAppAttestPoc",
    appleAppAttestRootCaPem = """
        -----BEGIN CERTIFICATE-----
        MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
        JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
        QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
        Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
        biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
        bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
        NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
        Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
        MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
        CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
        53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
        oyFraWVIyd/dganmrduC1bmTBGwD
        -----END CERTIFICATE-----
    """.trimIndent(),
    appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
)

// Validate a single attestation object. Throws an AttestationException if a validation error occurs.
val (publicKey, receipt) = attestation.validate(
    // See `iOS14-attestation-response-base64.cbor` for full attestation response
    attestationObjectBase64 = "o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JZAvYwggLyM ...",
    keyIdBase64 = "XGr5wqmUab/9M4b5vxa6KkPOigfeEWDaw7tuK02aJ6c=",
    serverChallenge = "wurzelpfropf".toByteArray()
)

// If the method call returns, the validation has passed and you can now trust the returned public key and receipt.
```

## Building

Just clone this respository

	git clone https://github.com/veehaitch/devicecheck-appattest.git
	
and build using Gradle

	./gradlew build
	
## License

[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html)
