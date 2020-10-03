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

            val serverResponseClock = Clock.fixed(Instant.parse("2020-10-03T09:13:53.54Z"), ZoneOffset.UTC)
            val date = DateTimeFormatter
                .RFC_1123_DATE_TIME
                .withZone(serverResponseClock.zone)
                .format(serverResponseClock.instant())

            val responseBody =
                """
                MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwGggCSABIID
                6DGCBHQwCQIBEQIBAQQBNTAPAgEGAgEBBAdSRUNFSVBUMDkCAQICAQEEMTZNVVJMOFRBNTcuZGUu
                dmluY2VudC1oYXVwZXJ0LmFwcGxlLWFwcGF0dGVzdC1wb2MwggMDAgEDAgEBBIIC+TCCAvUwggJ7
                oAMCAQICBgF07biyCTAKBggqhkjOPQQDAjBPMSMwIQYDVQQDDBpBcHBsZSBBcHAgQXR0ZXN0YXRp
                b24gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDEw
                MDIwOTA4NThaFw0yMDEwMDUwOTA4NThaMIGRMUkwRwYDVQQDDEA3ZGU4OTA2YzM5YmQ5YTFlZWY0
                MzExMDU1ZDM2OWUyNTA3MDFjOWM1ZWRkNWExOWY4MWZkMGZjMmFhNjgwNzMwMRowGAYDVQQLDBFB
                QUEgQ2VydGlmaWNhdGlvbjETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5p
                YTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNdnqIkkWZEGx4wL7FEDAtDQpZdOYSmd0xIAQLPm
                6A3pKDHRaDZr+hFpMt1/NWB1xr8ZlAzYcvd7kqVCanzaXFqjgf8wgfwwDAYDVR0TAQH/BAIwADAO
                BgNVHQ8BAf8EBAMCBPAwgYsGCSqGSIb3Y2QIBQR+MHykAwIBCr+JMAMCAQG/iTEDAgEAv4kyAwIB
                AL+JMwMCAQG/iTQzBDE2TVVSTDhUQTU3LmRlLnZpbmNlbnQtaGF1cGVydC5hcHBsZS1hcHBhdHRl
                c3QtcG9jpQYEBCBza3O/iTYDAgEFv4k3AwIBAL+JOQMCAQC/iToDAgEAMBkGCSqGSIb3Y2QIBwQM
                MAq/ingGBAQxNC4yMDMGCSqGSIb3Y2QIAgQmMCShIgQgrdTTFFYVuwaViLkEvl+TSc+dERqJvb7B
                lus6pTTWmmUwCgYIKoZIzj0EAwIDaAAwZQIwYCLJdzcW42G4vTtLxn1rd/UjJ3dqjSG9KarqApIZ
                huy+lsq/K0rKGqCkyOYDCuDnAjEAgbLtTegrtUpOxw2rTnQTwu6vCWA+0NP6syJ24yPe6fqy0P7T
                YCccg3TXG0Po6A+FMD4CAQQCAQEENu+/ve+/vVzvv71RWtCX77+9U++/vX0Y77+9Ne+/vW3XihQu
                77+977+9d1Jr77+9Eca+77+9ezBgAgEFAgEBBFhMZHRVaXZ3cDYySkNhdFRSRVorT0o4OWE4aXBk
                U29jVWtncENmL3NWNStKbjNzNHBQSVZUYU41bkt4blEEgZA3Vzk4ZnBRcy9idHAzR1dUZlNoY0hr
                UW1kZz09MA8CAQcCAQEEB3NhbmRib3gwHwIBDAIBAQQXMjAyMC0xMC0wM1QwOToxMzo1My41NFow
                HwIBEwIBAQQXMjAyMC0xMC0wNFQwOToxMzo1My41NFowHwIBFQIBAQQXMjAyMS0wMS0wMVQwOTox
                Mzo1My41NFoAAAAAAACggDCCA60wggNUoAMCAQICEFkzVq3lWYLPREI3rN9FG1MwCgYIKoZIzj0E
                AwIwfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcxMSYw
                JAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5j
                LjELMAkGA1UEBhMCVVMwHhcNMjAwNTE5MTc0NzMxWhcNMjEwNjE4MTc0NzMxWjBaMTYwNAYDVQQD
                DC1BcHBsaWNhdGlvbiBBdHRlc3RhdGlvbiBGcmF1ZCBSZWNlaXB0IFNpZ25pbmcxEzARBgNVBAoM
                CkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf+kVNGzD
                inuYPJPR0ENf2KvaVnAE0yxYhmVRlXq0ePfLKvi6Rff6eOrGLEnk+c3AhLUDFPECM9qbdvpEKiu4
                cqOCAdgwggHUMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU2Rf+S2eQOEuS9NvO1VeAFAuPPckw
                QwYIKwYBBQUHAQEENzA1MDMGCCsGAQUFBzABhidodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAz
                LWFhaWNhNWcxMDEwggEcBgNVHSAEggETMIIBDzCCAQsGCSqGSIb3Y2QFATCB/TCBwwYIKwYBBQUH
                AgIwgbYMgbNSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5IGFueSBwYXJ0eSBhc3N1bWVz
                IGFjY2VwdGFuY2Ugb2YgdGhlIHRoZW4gYXBwbGljYWJsZSBzdGFuZGFyZCB0ZXJtcyBhbmQgY29u
                ZGl0aW9ucyBvZiB1c2UsIGNlcnRpZmljYXRlIHBvbGljeSBhbmQgY2VydGlmaWNhdGlvbiBwcmFj
                dGljZSBzdGF0ZW1lbnRzLjA1BggrBgEFBQcCARYpaHR0cDovL3d3dy5hcHBsZS5jb20vY2VydGlm
                aWNhdGVhdXRob3JpdHkwHQYDVR0OBBYEFGkexw9H7OON3XU3RPPp4VpsEFYlMA4GA1UdDwEB/wQE
                AwIHgDAPBgkqhkiG92NkDA8EAgUAMAoGCCqGSM49BAMCA0cAMEQCICUYFlxeKZxZ9oU5rV3bmfY3
                PvYOzQhFqf13GtYkLSwiAiBdKpsqX6ujY4FljRhA969IC9droZTYNCCH9NaTW7UbrjCCAvkwggJ/
                oAMCAQICEFb7g9Qr/43DN5kjtVqubr0wCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9v
                dCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UE
                CgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTkwMzIyMTc1MzMzWhcNMzQwMzIyMDAwMDAw
                WjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAk
                BgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMu
                MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJLOY719hrGrKAo7HOGv+wSU
                gJGs9jHfpssoNW9ES+Eh5VfdEo2NuoJ8lb5J+r4zyq7NBBnxL0Ml+vS+s8uDfrqjgfcwgfQwDwYD
                VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBS7sN6hWDOImqSKmd6+veuv2sskqzBGBggrBgEFBQcB
                AQQ6MDgwNgYIKwYBBQUHMAGGKmh0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYXBwbGVyb290
                Y2FnMzA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vY3JsLmFwcGxlLmNvbS9hcHBsZXJvb3RjYWcz
                LmNybDAdBgNVHQ4EFgQU2Rf+S2eQOEuS9NvO1VeAFAuPPckwDgYDVR0PAQH/BAQDAgEGMBAGCiqG
                SIb3Y2QGAgMEAgUAMAoGCCqGSM49BAMDA2gAMGUCMQCNb6afoeDk7FtOc4qSfz14U5iP9NofWB7D
                dUr+OKhMKoMaGqoNpmRt4bmT6NFVTO0CMGc7LLTh6DcHd8vV7HaoGjpVOz81asjF5pKw4WG+gElp
                5F8rqWzhEQKqzGHZOLdzSjCCAkMwggHJoAMCAQICCC3F/IjSxUuVMAoGCCqGSM49BAMDMGcxGzAZ
                BgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBB
                dXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE0MDQzMDE4MTkw
                NloXDTM5MDQzMDE4MTkwNlowZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQL
                DB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkG
                A1UEBhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASY6S89QHKk7ZMicoETHN0QlfHFo05x3BQW
                2Q7lpgUqd2R7X04407scRLV/9R+2MmJdyemEW08wTxFaAP1YWAyl9Q8sTQdHE3Xal5eXbzFc7Sud
                eyA72LlU2V6ZpDpRCjGjQjBAMB0GA1UdDgQWBBS7sN6hWDOImqSKmd6+veuv2sskqzAPBgNVHRMB
                Af8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEAg+nBxBZeGl00GNnt
                7/RsDgBGS7jfskYRxQ/95nqMoaZrzsID1Jz1k8Z0uGrfqiMVAjBtZooQytQN1E/NjUM+tIpjpTNu
                423aF7dkH8hTJvmIYnQ5Cxdby1GoDOgYA+eisigAADGCAZUwggGRAgEBMIGQMHwxMDAuBgNVBAMM
                J0FwcGxlIEFwcGxpY2F0aW9uIEludGVncmF0aW9uIENBIDUgLSBHMTEmMCQGA1UECwwdQXBwbGUg
                Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVT
                AhBZM1at5VmCz0RCN6zfRRtTMA0GCWCGSAFlAwQCAQUAoIGVMBgGCSqGSIb3DQEJAzELBgkqhkiG
                9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIwMTAwMzA5MTM1M1owKgYJKoZIhvcNAQk0MR0wGzANBglg
                hkgBZQMEAgEFAKEKBggqhkjOPQQDAjAvBgkqhkiG9w0BCQQxIgQg2GI/J/vHG/wBPGAgekK/TPzS
                K6ITVN7QzzY+4sqM3WgwCgYIKoZIzj0EAwIERjBEAiA67xkgOwzVB08TLAzsc8n4I568q85BLMsW
                xzw/XPedkwIgaJJWWf0Q/yZBXOAkImWEg3/NecFhOMevKEcS80jrVQEAAAAAAAA=
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
            receipt.payload.riskMetric shouldBe 5

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

            val rec = receiptExchange.trade(
                receiptP7 = attestationResponse.receipt.p7,
                attestationPublicKey = attestationResponse.publicKey
            )
            print(rec)
        }
    }
}
