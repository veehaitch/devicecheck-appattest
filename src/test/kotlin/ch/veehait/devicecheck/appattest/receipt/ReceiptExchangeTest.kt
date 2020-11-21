package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.TestUtils
import ch.veehait.devicecheck.appattest.attestation.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.util.Extensions.fromBase64
import ch.veehait.devicecheck.appattest.util.Extensions.toBase64
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.comparables.shouldBeGreaterThan
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.ints.shouldBeGreaterThanOrEqual
import io.kotest.matchers.shouldBe
import nl.jqno.equalsverifier.EqualsVerifier
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class ReceiptExchangeTest : StringSpec() {

    init {

        "AppleReceiptHttpClientAdapter.Response: equals/hashCode" {
            EqualsVerifier.forClass(AppleReceiptExchangeHttpClientAdapter.Response::class.java).verify()
        }

        "ReceiptExchange works with MockWebServer" {
            val (attestationSample, app, attestationClock) = TestUtils.loadValidAttestationSample()

            val appleAppAttest = AppleAppAttest(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            )
            val attestationValidator = appleAppAttest.createAttestationValidator(
                clock = attestationClock,
                receiptValidator = appleAppAttest.createReceiptValidator(
                    clock = attestationClock
                )
            )
            val attestationResponse = attestationValidator.validate(
                attestationObject = attestationSample.attestation,
                keyIdBase64 = attestationSample.keyId.toBase64(),
                serverChallenge = attestationSample.clientData
            )

            val serverResponseClock = Clock.fixed(Instant.parse("2020-11-01T21:47:56.516Z"), ZoneOffset.UTC)
            val date = DateTimeFormatter
                .RFC_1123_DATE_TIME
                .withZone(serverResponseClock.zone)
                .format(serverResponseClock.instant())

            val responseBody =
                """
                MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwGggCSABIID
                6DGCBHowCQIBEQIBAQQBMTAPAgEGAgEBBAdSRUNFSVBUMDkCAQICAQEEMTZNVVJMOFRBNTcuZGUu
                dmluY2VudC1oYXVwZXJ0LmFwcGxlLWFwcGF0dGVzdC1wb2MwggMGAgEDAgEBBIIC/DCCAvgwggJ+
                oAMCAQICBgF1hcLfYTAKBggqhkjOPQQDAjBPMSMwIQYDVQQDDBpBcHBsZSBBcHAgQXR0ZXN0YXRp
                b24gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDEw
                MzEyMTQyMjJaFw0yMDExMDMyMTQyMjJaMIGRMUkwRwYDVQQDDEA3MTg3MThiMTUyY2RkZWY3M2Ez
                YWI2YTAxY2FhZDZhNzk2Nzc1MjZmMjcwOWMzNGE1NWE3NmYxYTAzM2U1N2FhMRowGAYDVQQLDBFB
                QUEgQ2VydGlmaWNhdGlvbjETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5p
                YTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABASxEyzw9tkgFAgMzVKfHuPoAlx8+XxKACBCijMe
                3njGpQvxmF/uUKX5hodaRCA2InU3lPi7VtTu/iDFCRi0M7+jggEBMIH+MAwGA1UdEwEB/wQCMAAw
                DgYDVR0PAQH/BAQDAgTwMIGLBgkqhkiG92NkCAUEfjB8pAMCAQq/iTADAgEBv4kxAwIBAL+JMgMC
                AQG/iTMDAgEBv4k0MwQxNk1VUkw4VEE1Ny5kZS52aW5jZW50LWhhdXBlcnQuYXBwbGUtYXBwYXR0
                ZXN0LXBvY6UGBARza3Mgv4k2AwIBBb+JNwMCAQC/iTkDAgEAv4k6AwIBADAbBgkqhkiG92NkCAcE
                DjAMv4p4CAQGMTQuMS4xMDMGCSqGSIb3Y2QIAgQmMCShIgQgI2t2cfOtuJjq369zxFMHoqRwl/js
                7Ojw5oYLjvq+1BgwCgYIKoZIzj0EAwIDaAAwZQIxAPyn6gtbiD/M2Lbk31JYEkWYUkMMMQqbnu9G
                UDXBPagh3XH7Mm5bJhJKxFINv40rKgIwWsVtOgxVg8GdFgZIBw/zA8x4O+G3KIMg8eK19yeWPeaE
                9ZwVzQK2zLMWlAu7nyrRMD4CAQQCAQEENu+/ve+/vVzvv71RWtCX77+9U++/vX0Y77+9Ne+/vW3X
                ihQu77+977+9d1Jr77+9Eca+77+9ezBgAgEFAgEBBFh4bkdRa3ZCdlRIb0lSb1Jrb1VLYWxiYjha
                MUpQcEZXUHZLeWJVVlZ0WmxWczVXUHpYYm9Gd04rWUIEgZZ1a3ppSmpSNHk2ZDV0cXFZL1FRVjEy
                L2o0UmdLUT09MA8CAQcCAQEEB3NhbmRib3gwIAIBDAIBAQQYMjAyMC0xMS0wMVQyMTo0Nzo1Ni41
                MTZaMCACARMCAQEEGDIwMjAtMTEtMDJUMjE6NDc6NTYuNTE2WjAgAgEVAgEBBBgyMDIxLTAxLTMw
                VDIxOjQ3OjU2LjUxNloAAAAAAACggDCCA60wggNUoAMCAQICEFkzVq3lWYLPREI3rN9FG1MwCgYI
                KoZIzj0EAwIwfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAt
                IEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBw
                bGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMjAwNTE5MTc0NzMxWhcNMjEwNjE4MTc0NzMxWjBaMTYw
                NAYDVQQDDC1BcHBsaWNhdGlvbiBBdHRlc3RhdGlvbiBGcmF1ZCBSZWNlaXB0IFNpZ25pbmcxEzAR
                BgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
                f+kVNGzDinuYPJPR0ENf2KvaVnAE0yxYhmVRlXq0ePfLKvi6Rff6eOrGLEnk+c3AhLUDFPECM9qb
                dvpEKiu4cqOCAdgwggHUMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU2Rf+S2eQOEuS9NvO1VeA
                FAuPPckwQwYIKwYBBQUHAQEENzA1MDMGCCsGAQUFBzABhidodHRwOi8vb2NzcC5hcHBsZS5jb20v
                b2NzcDAzLWFhaWNhNWcxMDEwggEcBgNVHSAEggETMIIBDzCCAQsGCSqGSIb3Y2QFATCB/TCBwwYI
                KwYBBQUHAgIwgbYMgbNSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5IGFueSBwYXJ0eSBh
                c3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIHRoZW4gYXBwbGljYWJsZSBzdGFuZGFyZCB0ZXJtcyBh
                bmQgY29uZGl0aW9ucyBvZiB1c2UsIGNlcnRpZmljYXRlIHBvbGljeSBhbmQgY2VydGlmaWNhdGlv
                biBwcmFjdGljZSBzdGF0ZW1lbnRzLjA1BggrBgEFBQcCARYpaHR0cDovL3d3dy5hcHBsZS5jb20v
                Y2VydGlmaWNhdGVhdXRob3JpdHkwHQYDVR0OBBYEFGkexw9H7OON3XU3RPPp4VpsEFYlMA4GA1Ud
                DwEB/wQEAwIHgDAPBgkqhkiG92NkDA8EAgUAMAoGCCqGSM49BAMCA0cAMEQCICUYFlxeKZxZ9oU5
                rV3bmfY3PvYOzQhFqf13GtYkLSwiAiBdKpsqX6ujY4FljRhA969IC9droZTYNCCH9NaTW7UbrjCC
                AvkwggJ/oAMCAQICEFb7g9Qr/43DN5kjtVqubr0wCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBw
                bGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTET
                MBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTkwMzIyMTc1MzMzWhcNMzQwMzIy
                MDAwMDAwWjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0g
                RzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBs
                ZSBJbmMuMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJLOY719hrGrKAo7
                HOGv+wSUgJGs9jHfpssoNW9ES+Eh5VfdEo2NuoJ8lb5J+r4zyq7NBBnxL0Ml+vS+s8uDfrqjgfcw
                gfQwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBS7sN6hWDOImqSKmd6+veuv2sskqzBGBggr
                BgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYXBw
                bGVyb290Y2FnMzA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vY3JsLmFwcGxlLmNvbS9hcHBsZXJv
                b3RjYWczLmNybDAdBgNVHQ4EFgQU2Rf+S2eQOEuS9NvO1VeAFAuPPckwDgYDVR0PAQH/BAQDAgEG
                MBAGCiqGSIb3Y2QGAgMEAgUAMAoGCCqGSM49BAMDA2gAMGUCMQCNb6afoeDk7FtOc4qSfz14U5iP
                9NofWB7DdUr+OKhMKoMaGqoNpmRt4bmT6NFVTO0CMGc7LLTh6DcHd8vV7HaoGjpVOz81asjF5pKw
                4WG+gElp5F8rqWzhEQKqzGHZOLdzSjCCAkMwggHJoAMCAQICCC3F/IjSxUuVMAoGCCqGSM49BAMD
                MGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNh
                dGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE0MDQz
                MDE4MTkwNloXDTM5MDQzMDE4MTkwNlowZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYw
                JAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5j
                LjELMAkGA1UEBhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASY6S89QHKk7ZMicoETHN0QlfHF
                o05x3BQW2Q7lpgUqd2R7X04407scRLV/9R+2MmJdyemEW08wTxFaAP1YWAyl9Q8sTQdHE3Xal5eX
                bzFc7SudeyA72LlU2V6ZpDpRCjGjQjBAMB0GA1UdDgQWBBS7sN6hWDOImqSKmd6+veuv2sskqzAP
                BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEAg+nBxBZe
                Gl00GNnt7/RsDgBGS7jfskYRxQ/95nqMoaZrzsID1Jz1k8Z0uGrfqiMVAjBtZooQytQN1E/NjUM+
                tIpjpTNu423aF7dkH8hTJvmIYnQ5Cxdby1GoDOgYA+eisigAADGB/jCB+wIBATCBkDB8MTAwLgYD
                VQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFw
                cGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQG
                EwJVUwIQWTNWreVZgs9EQjes30UbUzANBglghkgBZQMEAgEFADAKBggqhkjOPQQDAgRIMEYCIQCz
                et1+GSwJyd5+sRwSLbbuDH+00pg+RWtVIt2Oj6MOnwIhAI5wcuqhRD+XMKspNApV8z+pXfi33srH
                TANfnY7Te/VyAAAAAAAA
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
            val receiptExchange = appleAppAttest.createReceiptExchange(
                appleJwsGenerator = AppleJwsGeneratorImpl(
                    teamIdentifier = attestationSample.teamIdentifier,
                    keyIdentifier = "WURZELPFRO",
                    privateKeyPem =
                        """
                        -----BEGIN PRIVATE KEY-----
                        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWv4sxtqGFHysyUui
                        /vqP5WnExt9LGlh+4+Gb1YGqSz6hRANCAATeCV67+77uQmkBx13ATcE45v+CM1Wm
                        qrZEaNW3gX1JVxnJpOEaSwdvGr6moRGwq+7MrhI9Mlmx4uI+S2A0oR9B
                        -----END PRIVATE KEY-----
                        """.trimIndent(),
                    clock = serverResponseClock,
                ),
                receiptValidator = appleAppAttest.createReceiptValidator(
                    clock = serverResponseClock,
                ),
                appleDeviceCheckUrl = mockWebServerUri,
            )

            val receipt = receiptExchange.trade(
                receiptP7 = attestationResponse.receipt.p7,
                attestationPublicKey = attestationResponse.publicKey
            )

            mockWebServer.shutdown()

            receipt.p7 shouldBe mockResponse.getBody()!!.readByteArray().fromBase64()

            with(receipt.payload) {
                appId.value shouldBe app.appIdentifier
                attestationCertificate.value.publicKey shouldBe attestationResponse.publicKey
                clientHash.value shouldBe "77+977+9XO+/vVFa0Jfvv71T77+9fRjvv70177+9bdeKFC7vv73vv713Umvvv70Rxr7vv717".fromBase64()
                creationTime.value shouldBe Instant.parse("2020-11-01T21:47:56.516Z")
                environment?.value shouldBe "sandbox"
                expirationTime.value shouldBe creationTime.value.plus(Duration.ofDays(90))
                // XXX: this doesn't make a lot of sense.
                notBefore?.value shouldBe creationTime.value.plus(Duration.ofDays(1))
                riskMetric?.value shouldBe 1
                token.value shouldBe "xnGQkvBvTHoIRoRkoUKalbb8Z1JPpFWPvKybUVVtZlVs5WPzXboFwN+YBukziJjR4y6d5tqqY/QQV12/j4RgKQ=="
                type.value shouldBe Receipt.Type.RECEIPT
            }
        }

        val appleDeviceCheckKid = "94M3Z58NQ7"
        val appleDeviceCheckPrivateKeyPem = System.getenv("APPLE_KEY_P8_$appleDeviceCheckKid")

        "receipt exchange works".config(enabled = appleDeviceCheckPrivateKeyPem != null) {
            // Test setup
            val (attestationSample, app, attestationClock) = TestUtils.loadValidAttestationSample()

            val appleAppAttest = AppleAppAttest(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            )
            val attestationValidator = appleAppAttest.createAttestationValidator(
                clock = attestationClock,
                receiptValidator = appleAppAttest.createReceiptValidator(
                    clock = attestationClock
                )
            )
            val attestationResponse = attestationValidator.validate(
                attestationObject = attestationSample.attestation,
                keyIdBase64 = attestationSample.keyId.toBase64(),
                serverChallenge = attestationSample.clientData
            )

            // Actual test
            val receiptExchange = appleAppAttest.createReceiptExchange(
                appleJwsGenerator = AppleJwsGeneratorImpl(
                    teamIdentifier = attestationSample.teamIdentifier,
                    keyIdentifier = appleDeviceCheckKid,
                    privateKeyPem = appleDeviceCheckPrivateKeyPem
                ),
                receiptValidator = appleAppAttest.createReceiptValidator(),
            )

            val receipt = receiptExchange.trade(
                receiptP7 = attestationResponse.receipt.p7,
                attestationPublicKey = attestationResponse.publicKey
            )

            with(receipt.payload) {
                appId.value shouldBe app.appIdentifier
                attestationCertificate.value.publicKey shouldBe attestationResponse.publicKey
                clientHash.value shouldBe "77+977+9XO+/vVFa0Jfvv71T77+9fRjvv70177+9bdeKFC7vv73vv713Umvvv70Rxr7vv717".fromBase64()
                creationTime.value shouldBeGreaterThan Instant.now().minus(Duration.ofMinutes(5))
                creationTime.value shouldBeLessThan Instant.now().plus(Duration.ofMinutes(5))
                environment?.value shouldBe "sandbox"
                expirationTime.value shouldBe creationTime.value.plus(Duration.ofDays(90))
                // XXX: this doesn't make a lot of sense.
                notBefore?.value shouldBe creationTime.value.plus(Duration.ofDays(1))
                riskMetric!!.value shouldBeGreaterThanOrEqual 1
                token.value shouldBe "xnGQkvBvTHoIRoRkoUKalbb8Z1JPpFWPvKybUVVtZlVs5WPzXboFwN+YBukziJjR4y6d5tqqY/QQV12/j4RgKQ=="
                type.value shouldBe Receipt.Type.RECEIPT
            }
        }
    }
}
