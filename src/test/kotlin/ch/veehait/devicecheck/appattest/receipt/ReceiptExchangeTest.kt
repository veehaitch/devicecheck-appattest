package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.TestUtils
import ch.veehait.devicecheck.appattest.attestation.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.util.Extensions.fromBase64
import ch.veehait.devicecheck.appattest.util.Extensions.toBase64
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

            val serverResponseClock = Clock.fixed(Instant.parse("2020-10-22T17:21:33.761Z"), ZoneOffset.UTC)
            val date = DateTimeFormatter
                .RFC_1123_DATE_TIME
                .withZone(serverResponseClock.zone)
                .format(serverResponseClock.instant())

            val responseBody =
                """
                MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwGggCSABIID
                6DGCBHYwCQIBEQIBAQQBMzAPAgEGAgEBBAdSRUNFSVBUMDkCAQICAQEEMTZNVVJMOFRBNTcuZGUu
                dmluY2VudC1oYXVwZXJ0LmFwcGxlLWFwcGF0dGVzdC1wb2MwggMCAgEDAgEBBIIC+DCCAvQwggJ7
                oAMCAQICBgF1UUFK/DAKBggqhkjOPQQDAjBPMSMwIQYDVQQDDBpBcHBsZSBBcHAgQXR0ZXN0YXRp
                b24gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDEw
                MjExNzAwMzRaFw0yMDEwMjQxNzAwMzRaMIGRMUkwRwYDVQQDDEA0Mzk2OTE0MWY0ZTdiNmI0NTdi
                OWExNWMzMzEzOTA0ZjlhMWI5NGQwYmJjODQzZWRlZjU2ZWYyZThiOWUxMjQxMRowGAYDVQQLDBFB
                QUEgQ2VydGlmaWNhdGlvbjETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5p
                YTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIQONb2ffZVQeK3Vj7ySBecVw3H5buLgzclejixB
                G5cmy6B7OEDQ0aoB3UpCi+YvpPhG4q15Dlxj2bP7O0+npUCjgf8wgfwwDAYDVR0TAQH/BAIwADAO
                BgNVHQ8BAf8EBAMCBPAwgYsGCSqGSIb3Y2QIBQR+MHykAwIBCr+JMAMCAQG/iTEDAgEAv4kyAwIB
                AL+JMwMCAQG/iTQzBDE2TVVSTDhUQTU3LmRlLnZpbmNlbnQtaGF1cGVydC5hcHBsZS1hcHBhdHRl
                c3QtcG9jpQYEBCBza3O/iTYDAgEFv4k3AwIBAL+JOQMCAQC/iToDAgEAMBkGCSqGSIb3Y2QIBwQM
                MAq/ingGBAQxNC4yMDMGCSqGSIb3Y2QIAgQmMCShIgQgdZSdpJShcH16T199wFVVHW4pIl1ktyuX
                eSpSzpPFlFgwCgYIKoZIzj0EAwIDZwAwZAIwHXiZzEPDa4erTnChXOJiXlDuM+ArGXPlJR3WpyV0
                KVZPLPVWBGmBZA65dsnfiy/eAjBhp5/juiu6nNVWG6QAJwxVE/hTzaOw3LovBR8CXg3sqOE/d1v/
                IBdxIZB0X2cXsGUwPgIBBAIBAQQ277+977+9XO+/vVFa0Jfvv71T77+9fRjvv70177+9bdeKFC7v
                v73vv713Umvvv70Rxr7vv717MGACAQUCAQEEWEg4QXMzTFVRLzZRb2pGOFlmdUtXMHR0enVwbUVp
                Vzc3SnI1OUZwbDI2NnI2aTJveFRDa0RPenZjZG9SQnIEgZJaNFdXR2x2eDh0MlZYWExkK1ZCT0Fx
                SWJ3PT0wDwIBBwIBAQQHc2FuZGJveDAgAgEMAgEBBBgyMDIwLTEwLTIyVDE3OjIxOjMzLjc2MVow
                IAIBEwIBAQQYMjAyMC0xMC0yM1QxNzoyMTozMy43NjFaMCACARUCAQEEGDIwMjEtMDEtMjBUMTc6
                MjE6MzMuNzYxWgAAAAAAAKCAMIIDrTCCA1SgAwIBAgIQWTNWreVZgs9EQjes30UbUzAKBggqhkjO
                PQQDAjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzEx
                JjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJ
                bmMuMQswCQYDVQQGEwJVUzAeFw0yMDA1MTkxNzQ3MzFaFw0yMTA2MTgxNzQ3MzFaMFoxNjA0BgNV
                BAMMLUFwcGxpY2F0aW9uIEF0dGVzdGF0aW9uIEZyYXVkIFJlY2VpcHQgU2lnbmluZzETMBEGA1UE
                CgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR/6RU0
                bMOKe5g8k9HQQ1/Yq9pWcATTLFiGZVGVerR498sq+LpF9/p46sYsSeT5zcCEtQMU8QIz2pt2+kQq
                K7hyo4IB2DCCAdQwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTZF/5LZ5A4S5L0287VV4AUC489
                yTBDBggrBgEFBQcBAQQ3MDUwMwYIKwYBBQUHMAGGJ2h0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3Nw
                MDMtYWFpY2E1ZzEwMTCCARwGA1UdIASCARMwggEPMIIBCwYJKoZIhvdjZAUBMIH9MIHDBggrBgEF
                BQcCAjCBtgyBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3Vt
                ZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
                b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHBy
                YWN0aWNlIHN0YXRlbWVudHMuMDUGCCsGAQUFBwIBFilodHRwOi8vd3d3LmFwcGxlLmNvbS9jZXJ0
                aWZpY2F0ZWF1dGhvcml0eTAdBgNVHQ4EFgQUaR7HD0fs443ddTdE8+nhWmwQViUwDgYDVR0PAQH/
                BAQDAgeAMA8GCSqGSIb3Y2QMDwQCBQAwCgYIKoZIzj0EAwIDRwAwRAIgJRgWXF4pnFn2hTmtXduZ
                9jc+9g7NCEWp/Xca1iQtLCICIF0qmypfq6NjgWWNGED3r0gL12uhlNg0IIf01pNbtRuuMIIC+TCC
                An+gAwIBAgIQVvuD1Cv/jcM3mSO1Wq5uvTAKBggqhkjOPQQDAzBnMRswGQYDVQQDDBJBcHBsZSBS
                b290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYD
                VQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0xOTAzMjIxNzUzMzNaFw0zNDAzMjIwMDAw
                MDBaMHwxMDAuBgNVBAMMJ0FwcGxlIEFwcGxpY2F0aW9uIEludGVncmF0aW9uIENBIDUgLSBHMTEm
                MCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIElu
                Yy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEks5jvX2GsasoCjsc4a/7
                BJSAkaz2Md+myyg1b0RL4SHlV90SjY26gnyVvkn6vjPKrs0EGfEvQyX69L6zy4N+uqOB9zCB9DAP
                BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFLuw3qFYM4iapIqZ3r6966/ayySrMEYGCCsGAQUF
                BwEBBDowODA2BggrBgEFBQcwAYYqaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcHBsZXJv
                b3RjYWczMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwuYXBwbGUuY29tL2FwcGxlcm9vdGNh
                ZzMuY3JsMB0GA1UdDgQWBBTZF/5LZ5A4S5L0287VV4AUC489yTAOBgNVHQ8BAf8EBAMCAQYwEAYK
                KoZIhvdjZAYCAwQCBQAwCgYIKoZIzj0EAwMDaAAwZQIxAI1vpp+h4OTsW05zipJ/PXhTmI/02h9Y
                HsN1Sv44qEwqgxoaqg2mZG3huZPo0VVM7QIwZzsstOHoNwd3y9XsdqgaOlU7PzVqyMXmkrDhYb6A
                SWnkXyupbOERAqrMYdk4t3NKMIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEb
                MBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u
                IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgx
                OTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNV
                BAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQsw
                CQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHc
                FBbZDuWmBSp3ZHtfTjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVzt
                K517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySrMA8GA1Ud
                EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY
                2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK1A3UT82NQz60imOl
                M27jbdoXt2QfyFMm+YhidDkLF1vLUagM6BgD56KyKAAAMYH9MIH6AgEBMIGQMHwxMDAuBgNVBAMM
                J0FwcGxlIEFwcGxpY2F0aW9uIEludGVncmF0aW9uIENBIDUgLSBHMTEmMCQGA1UECwwdQXBwbGUg
                Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVT
                AhBZM1at5VmCz0RCN6zfRRtTMA0GCWCGSAFlAwQCAQUAMAoGCCqGSM49BAMCBEcwRQIhANC1EYrb
                OsY03sHKl9X7SDPa3+K22w5CVnaNASAlLNafAiBzYy6sStgxAx62Xa0z4U7s4SLoI4cbT5Jq5bxU
                n6o6bwAAAAAAAA==
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

            receipt.p7 shouldBe mockResponse.getBody()!!.readByteArray().fromBase64()
            receipt.payload.riskMetric?.value shouldBe 3

            mockWebServer.shutdown()
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

            receiptExchange.trade(
                receiptP7 = attestationResponse.receipt.p7,
                attestationPublicKey = attestationResponse.publicKey
            )
        }
    }
}
