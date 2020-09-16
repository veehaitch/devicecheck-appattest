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

            val serverResponseClock = Clock.fixed(Instant.parse("2020-09-16T05:58:31.094Z"), ZoneOffset.UTC)
            val date = DateTimeFormatter
                .RFC_1123_DATE_TIME
                .withZone(serverResponseClock.zone)
                .format(serverResponseClock.instant())

            val responseBody =
                """
                MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwGggCSABIID
                6DGCBHgwCgIBEQIBAQQCMTUwDwIBBgIBAQQHUkVDRUlQVDA5AgECAgEBBDE2TVVSTDhUQTU3LmRl
                LnZpbmNlbnQtaGF1cGVydC5hcHBsZS1hcHBhdHRlc3QtcG9jMIIDAwIBAwIBAQSCAvkwggL1MIIC
                e6ADAgECAgYBdJV3UgMwCgYIKoZIzj0EAwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0
                aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAw
                OTE1MDU1MDU5WhcNMjAwOTE4MDU1MDU5WjCBkTFJMEcGA1UEAwxANzBhY2M5YWYwMzhmOWRjYmEz
                Njg5ZWJhZTY5MWUwMTNhMjJmZWUxZDExNDhlOWFjOTZmNTAxM2E5MzExZTY0YTEaMBgGA1UECwwR
                QUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3Ju
                aWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASs2bvFY0J0GDsEVn+9Cx+RIOpb0Kp9jTS5N48S
                ooOKFsjvlQf5tydB+0PgDOkaJqHjifbtm8OmRkSTpRHdNgUso4H/MIH8MAwGA1UdEwEB/wQCMAAw
                DgYDVR0PAQH/BAQDAgTwMIGLBgkqhkiG92NkCAUEfjB8pAMCAQq/iTADAgEBv4kxAwIBAL+JMgMC
                AQC/iTMDAgEBv4k0MwQxNk1VUkw4VEE1Ny5kZS52aW5jZW50LWhhdXBlcnQuYXBwbGUtYXBwYXR0
                ZXN0LXBvY6UGBAQgc2tzv4k2AwIBBb+JNwMCAQC/iTkDAgEAv4k6AwIBADAZBgkqhkiG92NkCAcE
                DDAKv4p4BgQEMTQuMDAzBgkqhkiG92NkCAIEJjAkoSIEIAfOm7OBm8adGilofEnYHTD7nlFqLU+o
                qYWEDFdpGr2RMAoGCCqGSM49BAMCA2gAMGUCMQDQIClTCcnamphSWRVf1SGqfGlYWGXXU2fvx1qI
                EXUlvOCNJe70TDxzIZEnZ5YNqNECMEN5XzDbJwUglNlCZ9+VjkUZCPKC+bSIV0HX192SPwCLWBrX
                h7J7bk7S2CW+194eHzA+AgEEAgEBBDbvv73vv71c77+9UVrQl++/vVPvv719GO+/vTXvv71t14oU
                Lu+/ve+/vXdSa++/vRHGvu+/vXswYAIBBQIBAQRYcTliWDVDT1h0SG45SCtmQlpaZjIrNWhrdFpN
                bzFvMkI3ZExqMjdsRlNCckhZY0gwdkJRYWYwZUgyR2oEgZREdUdaKzhmakZpL2FRZWp0RGhISk54
                czNaOVE9PTAPAgEHAgEBBAdzYW5kYm94MCACAQwCAQEEGDIwMjAtMDktMTZUMDU6NTg6MzEuMDk0
                WjAgAgETAgEBBBgyMDIwLTA5LTE3VDA1OjU4OjMxLjA5NFowIAIBFQIBAQQYMjAyMC0xMi0xNVQw
                NTo1ODozMS4wOTRaAAAAAAAAoIAwggOtMIIDVKADAgECAhBZM1at5VmCz0RCN6zfRRtTMAoGCCqG
                SM49BAMCMHwxMDAuBgNVBAMMJ0FwcGxlIEFwcGxpY2F0aW9uIEludGVncmF0aW9uIENBIDUgLSBH
                MTEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxl
                IEluYy4xCzAJBgNVBAYTAlVTMB4XDTIwMDUxOTE3NDczMVoXDTIxMDYxODE3NDczMVowWjE2MDQG
                A1UEAwwtQXBwbGljYXRpb24gQXR0ZXN0YXRpb24gRnJhdWQgUmVjZWlwdCBTaWduaW5nMRMwEQYD
                VQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABH/p
                FTRsw4p7mDyT0dBDX9ir2lZwBNMsWIZlUZV6tHj3yyr4ukX3+njqxixJ5PnNwIS1AxTxAjPam3b6
                RCoruHKjggHYMIIB1DAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFNkX/ktnkDhLkvTbztVXgBQL
                jz3JMEMGCCsGAQUFBwEBBDcwNTAzBggrBgEFBQcwAYYnaHR0cDovL29jc3AuYXBwbGUuY29tL29j
                c3AwMy1hYWljYTVnMTAxMIIBHAYDVR0gBIIBEzCCAQ8wggELBgkqhkiG92NkBQEwgf0wgcMGCCsG
                AQUFBwICMIG2DIGzUmVsaWFuY2Ugb24gdGhpcyBjZXJ0aWZpY2F0ZSBieSBhbnkgcGFydHkgYXNz
                dW1lcyBhY2NlcHRhbmNlIG9mIHRoZSB0aGVuIGFwcGxpY2FibGUgc3RhbmRhcmQgdGVybXMgYW5k
                IGNvbmRpdGlvbnMgb2YgdXNlLCBjZXJ0aWZpY2F0ZSBwb2xpY3kgYW5kIGNlcnRpZmljYXRpb24g
                cHJhY3RpY2Ugc3RhdGVtZW50cy4wNQYIKwYBBQUHAgEWKWh0dHA6Ly93d3cuYXBwbGUuY29tL2Nl
                cnRpZmljYXRlYXV0aG9yaXR5MB0GA1UdDgQWBBRpHscPR+zjjd11N0Tz6eFabBBWJTAOBgNVHQ8B
                Af8EBAMCB4AwDwYJKoZIhvdjZAwPBAIFADAKBggqhkjOPQQDAgNHADBEAiAlGBZcXimcWfaFOa1d
                25n2Nz72Ds0IRan9dxrWJC0sIgIgXSqbKl+ro2OBZY0YQPevSAvXa6GU2DQgh/TWk1u1G64wggL5
                MIICf6ADAgECAhBW+4PUK/+NwzeZI7Varm69MAoGCCqGSM49BAMDMGcxGzAZBgNVBAMMEkFwcGxl
                IFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzAR
                BgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE5MDMyMjE3NTMzM1oXDTM0MDMyMjAw
                MDAwMFowfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcx
                MSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUg
                SW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASSzmO9fYaxqygKOxzh
                r/sElICRrPYx36bLKDVvREvhIeVX3RKNjbqCfJW+Sfq+M8quzQQZ8S9DJfr0vrPLg366o4H3MIH0
                MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUu7DeoVgziJqkipnevr3rr9rLJKswRgYIKwYB
                BQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxl
                cm9vdGNhZzMwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5hcHBsZS5jb20vYXBwbGVyb290
                Y2FnMy5jcmwwHQYDVR0OBBYEFNkX/ktnkDhLkvTbztVXgBQLjz3JMA4GA1UdDwEB/wQEAwIBBjAQ
                BgoqhkiG92NkBgIDBAIFADAKBggqhkjOPQQDAwNoADBlAjEAjW+mn6Hg5OxbTnOKkn89eFOYj/Ta
                H1gew3VK/jioTCqDGhqqDaZkbeG5k+jRVUztAjBnOyy04eg3B3fL1ex2qBo6VTs/NWrIxeaSsOFh
                voBJaeRfK6ls4RECqsxh2Ti3c0owggJDMIIByaADAgECAggtxfyI0sVLlTAKBggqhkjOPQQDAzBn
                MRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRp
                b24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0xNDA0MzAx
                ODE5MDZaFw0zOTA0MzAxODE5MDZaMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQG
                A1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4x
                CzAJBgNVBAYTAlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEmOkvPUBypO2TInKBExzdEJXxxaNO
                cdwUFtkO5aYFKndke19OONO7HES1f/UftjJiXcnphFtPME8RWgD9WFgMpfUPLE0HRxN12peXl28x
                XO0rnXsgO9i5VNlemaQ6UQoxo0IwQDAdBgNVHQ4EFgQUu7DeoVgziJqkipnevr3rr9rLJKswDwYD
                VR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIxAIPpwcQWXhpd
                NBjZ7e/0bA4ARku437JGEcUP/eZ6jKGma87CA9Sc9ZPGdLhq36ojFQIwbWaKEMrUDdRPzY1DPrSK
                Y6UzbuNt2he3ZB/IUyb5iGJ0OQsXW8tRqAzoGAPnorIoAAAxggGXMIIBkwIBATCBkDB8MTAwLgYD
                VQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFw
                cGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQG
                EwJVUwIQWTNWreVZgs9EQjes30UbUzANBglghkgBZQMEAgEFAKCBlTAYBgkqhkiG9w0BCQMxCwYJ
                KoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMDA5MTYwNTU4MzFaMCoGCSqGSIb3DQEJNDEdMBsw
                DQYJYIZIAWUDBAIBBQChCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIFhO+cKNKbjEYClfkHm4
                kgRjy1frdOo4JKZsmz61BUj9MAoGCCqGSM49BAMCBEgwRgIhAMEkvELXI6cZ4NujEJ2cOOGaqE/w
                vbC7jzOpiOm6XtkFAiEA9Y5SMgBLq+lZJ5Py4uFnUM608xEaG+TLl+6ATX98O+QAAAAAAAA=
                """.trimIndent()

            val mockResponse = MockResponse().apply {
                setHeader("Server", "Apple")
                setHeader("Date", date)
                setHeader("Content-Type", "base64")
                setHeader("Content-Length", responseBody.length.toString())
                setHeader("Connection", "keep-alive")
                setHeader("X-B3-TraceId", "6aa9ae171ae70fd9")
                setHeader("Strict-Transport-Security", "max-age=31536000; includeSubdomains")
                setHeader("X-Frame-Options", "SAMEORIGIN")
                setHeader("X-Content-Type-Options", "nosniff")
                setHeader("X-XSS-Protection", "1; mode=block")

                setResponseCode(200)
                setBody(responseBody)
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
            receipt.payload.riskMetric shouldBe 15

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
