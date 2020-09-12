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

            val serverResponseClock = Clock.fixed(Instant.parse("2020-09-12T15:43:29.000Z"), ZoneOffset.UTC)
            val date = DateTimeFormatter
                .RFC_1123_DATE_TIME
                .withZone(serverResponseClock.zone)
                .format(serverResponseClock.instant())

            val responseBody =
                """
                MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwGggCSABIID
                6DGCBHcwCgIBEQIBAQQCMTUwDwIBBgIBAQQHUkVDRUlQVDA5AgECAgEBBDE2TVVSTDhUQTU3LmRl
                LnZpbmNlbnQtaGF1cGVydC5hcHBsZS1hcHBhdHRlc3QtcG9jMIIDAgIBAwIBAQSCAvgwggL0MIIC
                e6ADAgECAgYBdILijBwwCgYIKoZIzj0EAwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0
                aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAw
                OTExMTUxNTE5WhcNMjAwOTE0MTUxNTE5WjCBkTFJMEcGA1UEAwxANTY0OGI4NmMxYmU1N2EwNDI5
                YTIzNjY2ZTYxMTA5YTJkODM5YjNhMjcyMTc5MDNjNzI1ODA5NDYxMmNiYzA0MjEaMBgGA1UECwwR
                QUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3Ju
                aWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS+xQY/rcfRC2Af0PfOxYUN08gNOdKw13xuUa8y
                oW9O7fp4fGXawDdZDuiJ4kY3wTg0ISf5WVYTA8ygCWm7crAJo4H/MIH8MAwGA1UdEwEB/wQCMAAw
                DgYDVR0PAQH/BAQDAgTwMIGLBgkqhkiG92NkCAUEfjB8pAMCAQq/iTADAgEBv4kxAwIBAL+JMgMC
                AQC/iTMDAgEBv4k0MwQxNk1VUkw4VEE1Ny5kZS52aW5jZW50LWhhdXBlcnQuYXBwbGUtYXBwYXR0
                ZXN0LXBvY6UGBAQgc2tzv4k2AwIBBb+JNwMCAQC/iTkDAgEAv4k6AwIBADAZBgkqhkiG92NkCAcE
                DDAKv4p4BgQEMTQuMDAzBgkqhkiG92NkCAIEJjAkoSIEIKU5Fzd3z8pTrAdChuHLAjbZQNiV4C+j
                ekMvwj6ty63gMAoGCCqGSM49BAMCA2cAMGQCMCdZrNJguTQUgbYci9NQUntWoBJJynwiNStx7a0O
                29YAhxyYf13JjDPLDXTeJIq/OAIway8FZrHaNIetFRpRYe8ZABjLC3pnnRFCYXtZ4FMUBu6fISs2
                5nMSGT3mxniJBAK2MD4CAQQCAQEENu+/ve+/vVzvv71RWtCX77+9U++/vX0Y77+9Ne+/vW3XihQu
                77+977+9d1Jr77+9Eca+77+9ezBgAgEFAgEBBFhXRkx6NGl4WjFkbkQ1ZXo4bklsSXY1aDNkWldR
                VVdLTTZBRUZSMXN1Y0d6TVVuMk5xOG5lV0FhMUQzWVMEgZNxN094b1l5YnNET1dYb1I2ZnNSQzNq
                U1hBUT09MA8CAQcCAQEEB3NhbmRib3gwIAIBDAIBAQQYMjAyMC0wOS0xMlQxNTo0MzoyOS4wOTha
                MCACARMCAQEEGDIwMjAtMDktMTNUMTU6NDM6MjkuMDk4WjAgAgEVAgEBBBgyMDIwLTEyLTExVDE1
                OjQzOjI5LjA5OFoAAAAAAACggDCCA60wggNUoAMCAQICEFkzVq3lWYLPREI3rN9FG1MwCgYIKoZI
                zj0EAwIwfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcx
                MSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUg
                SW5jLjELMAkGA1UEBhMCVVMwHhcNMjAwNTE5MTc0NzMxWhcNMjEwNjE4MTc0NzMxWjBaMTYwNAYD
                VQQDDC1BcHBsaWNhdGlvbiBBdHRlc3RhdGlvbiBGcmF1ZCBSZWNlaXB0IFNpZ25pbmcxEzARBgNV
                BAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf+kV
                NGzDinuYPJPR0ENf2KvaVnAE0yxYhmVRlXq0ePfLKvi6Rff6eOrGLEnk+c3AhLUDFPECM9qbdvpE
                Kiu4cqOCAdgwggHUMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU2Rf+S2eQOEuS9NvO1VeAFAuP
                PckwQwYIKwYBBQUHAQEENzA1MDMGCCsGAQUFBzABhidodHRwOi8vb2NzcC5hcHBsZS5jb20vb2Nz
                cDAzLWFhaWNhNWcxMDEwggEcBgNVHSAEggETMIIBDzCCAQsGCSqGSIb3Y2QFATCB/TCBwwYIKwYB
                BQUHAgIwgbYMgbNSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5IGFueSBwYXJ0eSBhc3N1
                bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIHRoZW4gYXBwbGljYWJsZSBzdGFuZGFyZCB0ZXJtcyBhbmQg
                Y29uZGl0aW9ucyBvZiB1c2UsIGNlcnRpZmljYXRlIHBvbGljeSBhbmQgY2VydGlmaWNhdGlvbiBw
                cmFjdGljZSBzdGF0ZW1lbnRzLjA1BggrBgEFBQcCARYpaHR0cDovL3d3dy5hcHBsZS5jb20vY2Vy
                dGlmaWNhdGVhdXRob3JpdHkwHQYDVR0OBBYEFGkexw9H7OON3XU3RPPp4VpsEFYlMA4GA1UdDwEB
                /wQEAwIHgDAPBgkqhkiG92NkDA8EAgUAMAoGCCqGSM49BAMCA0cAMEQCICUYFlxeKZxZ9oU5rV3b
                mfY3PvYOzQhFqf13GtYkLSwiAiBdKpsqX6ujY4FljRhA969IC9droZTYNCCH9NaTW7UbrjCCAvkw
                ggJ/oAMCAQICEFb7g9Qr/43DN5kjtVqubr0wCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUg
                Um9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEG
                A1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTkwMzIyMTc1MzMzWhcNMzQwMzIyMDAw
                MDAwWjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzEx
                JjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJ
                bmMuMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJLOY719hrGrKAo7HOGv
                +wSUgJGs9jHfpssoNW9ES+Eh5VfdEo2NuoJ8lb5J+r4zyq7NBBnxL0Ml+vS+s8uDfrqjgfcwgfQw
                DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBS7sN6hWDOImqSKmd6+veuv2sskqzBGBggrBgEF
                BQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYXBwbGVy
                b290Y2FnMzA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vY3JsLmFwcGxlLmNvbS9hcHBsZXJvb3Rj
                YWczLmNybDAdBgNVHQ4EFgQU2Rf+S2eQOEuS9NvO1VeAFAuPPckwDgYDVR0PAQH/BAQDAgEGMBAG
                CiqGSIb3Y2QGAgMEAgUAMAoGCCqGSM49BAMDA2gAMGUCMQCNb6afoeDk7FtOc4qSfz14U5iP9Nof
                WB7DdUr+OKhMKoMaGqoNpmRt4bmT6NFVTO0CMGc7LLTh6DcHd8vV7HaoGjpVOz81asjF5pKw4WG+
                gElp5F8rqWzhEQKqzGHZOLdzSjCCAkMwggHJoAMCAQICCC3F/IjSxUuVMAoGCCqGSM49BAMDMGcx
                GzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlv
                biBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE0MDQzMDE4
                MTkwNloXDTM5MDQzMDE4MTkwNlowZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYD
                VQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjEL
                MAkGA1UEBhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASY6S89QHKk7ZMicoETHN0QlfHFo05x
                3BQW2Q7lpgUqd2R7X04407scRLV/9R+2MmJdyemEW08wTxFaAP1YWAyl9Q8sTQdHE3Xal5eXbzFc
                7SudeyA72LlU2V6ZpDpRCjGjQjBAMB0GA1UdDgQWBBS7sN6hWDOImqSKmd6+veuv2sskqzAPBgNV
                HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEAg+nBxBZeGl00
                GNnt7/RsDgBGS7jfskYRxQ/95nqMoaZrzsID1Jz1k8Z0uGrfqiMVAjBtZooQytQN1E/NjUM+tIpj
                pTNu423aF7dkH8hTJvmIYnQ5Cxdby1GoDOgYA+eisigAADGCAZYwggGSAgEBMIGQMHwxMDAuBgNV
                BAMMJ0FwcGxlIEFwcGxpY2F0aW9uIEludGVncmF0aW9uIENBIDUgLSBHMTEmMCQGA1UECwwdQXBw
                bGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYT
                AlVTAhBZM1at5VmCz0RCN6zfRRtTMA0GCWCGSAFlAwQCAQUAoIGVMBgGCSqGSIb3DQEJAzELBgkq
                hkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIwMDkxMjE1NDMyOVowKgYJKoZIhvcNAQk0MR0wGzAN
                BglghkgBZQMEAgEFAKEKBggqhkjOPQQDAjAvBgkqhkiG9w0BCQQxIgQgi2/YWS8+y0GLQSbHQg4f
                A9kiawH8BZGz20YjCvCs3NwwCgYIKoZIzj0EAwIERzBFAiEAs2W07sQPIQDTGERPPoSMhmJytbUi
                nN3Bs9A+ZJf/lhECIE6oqtv+PUmiCO62bmR877p3UyQKFHBPqb4NYyqB79CuAAAAAAAA
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
