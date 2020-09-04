package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.Extensions.fromBase64
import ch.veehait.devicecheck.appattest.Extensions.toBase64
import ch.veehait.devicecheck.appattest.TestUtils
import ch.veehait.devicecheck.appattest.attestation.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.attestation.AttestationValidator
import ch.veehait.devicecheck.appattest.attestation.AttestationValidatorImpl
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import nl.jqno.equalsverifier.EqualsVerifier
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class ReceiptExchangeTest : StringSpec() {

    init {

        "AppleReceiptHttpClientAdapter.Response: equals/hashCode" {
            EqualsVerifier.forClass(AppleReceiptHttpClientAdapter.Response::class.java).verify()
        }

        "ReceiptExchange works with MockWebServer" {
            val (attestationSample, app, attestationClock) = TestUtils.loadValidAttestationSample()

            val attestationValidator: AttestationValidator = AttestationValidatorImpl(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT,
                clock = attestationClock
            )
            val attestationResponse = attestationValidator.validate(
                attestationObject = attestationSample.attestation,
                keyIdBase64 = attestationSample.keyId.toBase64(),
                serverChallenge = attestationSample.clientData
            )

            val serverResponseClock = Clock.fixed(Instant.parse("2020-09-02T09:17:15.00Z"), ZoneOffset.UTC)
            val date = DateTimeFormatter
                .RFC_1123_DATE_TIME
                .withZone(serverResponseClock.zone)
                .format(serverResponseClock.instant())

            val mockResponse = MockResponse().apply {
                setHeader("Server", "Apple")
                setHeader("Date", date)
                setHeader("Content-Type", "base64")
                setHeader("Content-Length", "5240")
                setHeader("Connection", "keep-alive")
                setHeader("X-B3-TraceId", "6aa9ae171ae70fd9")
                setHeader("Strict-Transport-Security", "max-age=31536000; includeSubdomains")
                setHeader("X-Frame-Options", "SAMEORIGIN")
                setHeader("X-Content-Type-Options", "nosniff")
                setHeader("X-XSS-Protection", "1; mode=block")

                setResponseCode(200)
                setBody(
                    """
                        MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwGggCSABIID
                        6DGCBHkwCgIBEQIBAQQCMTAwDwIBBgIBAQQHUkVDRUlQVDA5AgECAgEBBDE2TVVSTDhUQTU3LmRl
                        LnZpbmNlbnQtaGF1cGVydC5hcHBsZS1hcHBhdHRlc3QtcG9jMIIDBAIBAwIBAQSCAvowggL2MIIC
                        e6ADAgECAgYBdEO4Tx4wCgYIKoZIzj0EAwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0
                        aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAw
                        ODMxMDg0MzA2WhcNMjAwOTAxMDg1MzA2WjCBkTFJMEcGA1UEAwxAN2NmYjU2NzJjZDliNzUzNDhk
                        MGMyN2M0MWI3ZDc0Y2IxYWM3MDU0MjE2Yzc3MmM1ZDdlMTAyNzhiNTMwZTlmNDEaMBgGA1UECwwR
                        QUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3Ju
                        aWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARSJ6vh37RqxJAS0LkoVsqmUUYFkv2PFO/3mHE2
                        lO2EqatDbOp6wQFaA4h40APOxq/0hOR4nO8hSxtWhzYjwCQoo4H/MIH8MAwGA1UdEwEB/wQCMAAw
                        DgYDVR0PAQH/BAQDAgTwMIGLBgkqhkiG92NkCAUEfjB8pAMCAQq/iTADAgEBv4kxAwIBAL+JMgMC
                        AQC/iTMDAgEBv4k0MwQxNk1VUkw4VEE1Ny5kZS52aW5jZW50LWhhdXBlcnQuYXBwbGUtYXBwYXR0
                        ZXN0LXBvY6UGBAQgc2tzv4k2AwIBBb+JNwMCAQC/iTkDAgEAv4k6AwIBADAZBgkqhkiG92NkCAcE
                        DDAKv4p4BgQEMTQuMDAzBgkqhkiG92NkCAIEJjAkoSIEIEQ3OKc8FQ6BP5A6iw54vrjxbMVjlgoH
                        bWJ5r3Y3XN+gMAoGCCqGSM49BAMCA2kAMGYCMQCT10CU4BwXVpTPfdDKaPDFBOzbsp0R2ASfN+ly
                        MI4ZJryHjbpdjQwhiqI7BBD0GPcCMQDNrnsREXx/KX5mby8oIYo5d72asMXQ+JZ0V+Pd16ZEGwQk
                        Lv4lcheUnAI1hnxJ1WswPgIBBAIBAQQ277+977+9XO+/vVFa0Jfvv71T77+9fRjvv70177+9bdeK
                        FC7vv73vv713Umvvv70Rxr7vv717MGACAQUCAQEEWDQwZ2ZjZW51c3V5ZVRIMFducFgzcEZUaWdu
                        bVNmYng4ZUNPanNsK2ZuQ3ExeWVQWlFvNXg0UzRnc0cEgZVjY1d5cUg5UUliSUpraWRMWFdCYVVn
                        NngraUl3PT0wDwIBBwIBAQQHc2FuZGJveDAgAgEMAgEBBBgyMDIwLTA5LTAyVDA5OjE3OjE1LjYw
                        OVowIAIBEwIBAQQYMjAyMC0wOS0wM1QwOToxNzoxNS42MDlaMCACARUCAQEEGDIwMjAtMTItMDFU
                        MDk6MTc6MTUuNjA5WgAAAAAAAKCAMIIDrTCCA1SgAwIBAgIQWTNWreVZgs9EQjes30UbUzAKBggq
                        hkjOPQQDAjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0g
                        RzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBs
                        ZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yMDA1MTkxNzQ3MzFaFw0yMTA2MTgxNzQ3MzFaMFoxNjA0
                        BgNVBAMMLUFwcGxpY2F0aW9uIEF0dGVzdGF0aW9uIEZyYXVkIFJlY2VpcHQgU2lnbmluZzETMBEG
                        A1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR/
                        6RU0bMOKe5g8k9HQQ1/Yq9pWcATTLFiGZVGVerR498sq+LpF9/p46sYsSeT5zcCEtQMU8QIz2pt2
                        +kQqK7hyo4IB2DCCAdQwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTZF/5LZ5A4S5L0287VV4AU
                        C489yTBDBggrBgEFBQcBAQQ3MDUwMwYIKwYBBQUHMAGGJ2h0dHA6Ly9vY3NwLmFwcGxlLmNvbS9v
                        Y3NwMDMtYWFpY2E1ZzEwMTCCARwGA1UdIASCARMwggEPMIIBCwYJKoZIhvdjZAUBMIH9MIHDBggr
                        BgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFz
                        c3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFu
                        ZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9u
                        IHByYWN0aWNlIHN0YXRlbWVudHMuMDUGCCsGAQUFBwIBFilodHRwOi8vd3d3LmFwcGxlLmNvbS9j
                        ZXJ0aWZpY2F0ZWF1dGhvcml0eTAdBgNVHQ4EFgQUaR7HD0fs443ddTdE8+nhWmwQViUwDgYDVR0P
                        AQH/BAQDAgeAMA8GCSqGSIb3Y2QMDwQCBQAwCgYIKoZIzj0EAwIDRwAwRAIgJRgWXF4pnFn2hTmt
                        XduZ9jc+9g7NCEWp/Xca1iQtLCICIF0qmypfq6NjgWWNGED3r0gL12uhlNg0IIf01pNbtRuuMIIC
                        +TCCAn+gAwIBAgIQVvuD1Cv/jcM3mSO1Wq5uvTAKBggqhkjOPQQDAzBnMRswGQYDVQQDDBJBcHBs
                        ZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMw
                        EQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0xOTAzMjIxNzUzMzNaFw0zNDAzMjIw
                        MDAwMDBaMHwxMDAuBgNVBAMMJ0FwcGxlIEFwcGxpY2F0aW9uIEludGVncmF0aW9uIENBIDUgLSBH
                        MTEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxl
                        IEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEks5jvX2GsasoCjsc
                        4a/7BJSAkaz2Md+myyg1b0RL4SHlV90SjY26gnyVvkn6vjPKrs0EGfEvQyX69L6zy4N+uqOB9zCB
                        9DAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFLuw3qFYM4iapIqZ3r6966/ayySrMEYGCCsG
                        AQUFBwEBBDowODA2BggrBgEFBQcwAYYqaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcHBs
                        ZXJvb3RjYWczMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwuYXBwbGUuY29tL2FwcGxlcm9v
                        dGNhZzMuY3JsMB0GA1UdDgQWBBTZF/5LZ5A4S5L0287VV4AUC489yTAOBgNVHQ8BAf8EBAMCAQYw
                        EAYKKoZIhvdjZAYCAwQCBQAwCgYIKoZIzj0EAwMDaAAwZQIxAI1vpp+h4OTsW05zipJ/PXhTmI/0
                        2h9YHsN1Sv44qEwqgxoaqg2mZG3huZPo0VVM7QIwZzsstOHoNwd3y9XsdqgaOlU7PzVqyMXmkrDh
                        Yb6ASWnkXyupbOERAqrMYdk4t3NKMIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMw
                        ZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0
                        aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMw
                        MTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAk
                        BgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMu
                        MQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWj
                        TnHcFBbZDuWmBSp3ZHtfTjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dv
                        MVztK517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySrMA8G
                        A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4a
                        XTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK1A3UT82NQz60
                        imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM6BgD56KyKAAAMYIBljCCAZICAQEwgZAwfDEwMC4G
                        A1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcxMSYwJAYDVQQLDB1B
                        cHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UE
                        BhMCVVMCEFkzVq3lWYLPREI3rN9FG1MwDQYJYIZIAWUDBAIBBQCggZUwGAYJKoZIhvcNAQkDMQsG
                        CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAwOTAyMDkxNzE1WjAqBgkqhkiG9w0BCTQxHTAb
                        MA0GCWCGSAFlAwQCAQUAoQoGCCqGSM49BAMCMC8GCSqGSIb3DQEJBDEiBCCe6Fd6sHrE80QjOSkw
                        ZSMhj1D2Ik+3a80PN8bp8IHy6zAKBggqhkjOPQQDAgRHMEUCIQCzhzYKs9TxpemvgUZcAetTvpl0
                        bnLSpQa0h8t4tY2rRQIgHqsO+WOINrhsGdNZSENPevIJbktHDhjMAWTLiXTh60QAAAAAAAA=
                    """.trimIndent()
                )
            }

            val mockWebServer = MockWebServer().apply {
                enqueue(mockResponse)
            }

            mockWebServer.start()
            val mockWebServerUri = mockWebServer.url("/v1/attestationData").toUri()

            // Actual test
            val receiptExchange = ReceiptExchangeImpl(
                appleJwsGenerator = AppleJwsGeneratorImpl(
                    appleTeamIdentifier = attestationSample.teamIdentifier,
                    keyIdentifier = "WURZELPFRO",
                    privateKeyPem =
                        """
                        -----BEGIN PRIVATE KEY-----
                        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWv4sxtqGFHysyUui
                        /vqP5WnExt9LGlh+4+Gb1YGqSz6hRANCAATeCV67+77uQmkBx13ATcE45v+CM1Wm
                        qrZEaNW3gX1JVxnJpOEaSwdvGr6moRGwq+7MrhI9Mlmx4uI+S2A0oR9B
                        -----END PRIVATE KEY-----
                        """.trimIndent(),
                ),
                receiptValidator = ReceiptValidatorImpl(
                    app = app,
                    clock = serverResponseClock,
                ),
                appleDeviceCheckUrl = mockWebServerUri
            )

            val receipt = receiptExchange.trade(
                receiptP7 = attestationResponse.receipt.p7,
                attestationPublicKey = attestationResponse.publicKey
            )

            receipt.p7 shouldBe mockResponse.getBody()!!.readByteArray().fromBase64()
            receipt.payload.riskMetric shouldBe 10

            mockWebServer.shutdown()
        }

        val appleDeviceCheckKid = "94M3Z58NQ7"
        val appleDeviceCheckPrivateKeyPem = System.getenv("APPLE_KEY_P8_$appleDeviceCheckKid")

        "receipt exchange works".config(enabled = appleDeviceCheckPrivateKeyPem != null) {
            // Test setup
            val (attestationSample, app, clock) = TestUtils.loadValidAttestationSample()

            val attestationValidator: AttestationValidator = AttestationValidatorImpl(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT,
                clock = clock
            )
            val attestationResponse = attestationValidator.validate(
                attestationObject = attestationSample.attestation,
                keyIdBase64 = attestationSample.keyId.toBase64(),
                serverChallenge = attestationSample.clientData
            )

            // Actual test
            val receiptExchange = ReceiptExchangeImpl(
                appleJwsGenerator = AppleJwsGeneratorImpl(
                    appleTeamIdentifier = attestationSample.teamIdentifier,
                    keyIdentifier = appleDeviceCheckKid,
                    privateKeyPem = appleDeviceCheckPrivateKeyPem
                ),
                receiptValidator = ReceiptValidatorImpl(
                    app = app,
                ),
            )

            receiptExchange.trade(
                receiptP7 = attestationResponse.receipt.p7,
                attestationPublicKey = attestationResponse.publicKey
            )
        }
    }
}
