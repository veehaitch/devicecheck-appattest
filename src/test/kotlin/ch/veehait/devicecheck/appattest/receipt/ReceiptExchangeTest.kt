package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.CertUtils
import ch.veehait.devicecheck.appattest.CertUtils.toPEM
import ch.veehait.devicecheck.appattest.TestExtensions.readTextResource
import ch.veehait.devicecheck.appattest.TestUtils
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.util.Extensions.fromBase64
import ch.veehait.devicecheck.appattest.util.Extensions.toBase64
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.comparables.shouldBeGreaterThan
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.ints.shouldBeGreaterThanOrEqual
import io.kotest.matchers.shouldBe
import io.kotest.matchers.throwable.shouldHaveMessage
import nl.jqno.equalsverifier.EqualsVerifier
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.openssl.PEMParser
import java.net.http.HttpHeaders
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class ReceiptExchangeTest : StringSpec() {

    init {

        "AppleReceiptHttpClientAdapter.Response: equals/hashCode" {
            val red = HttpHeaders.of(mapOf("Content-Type" to listOf("red"))) { _, _ -> true }
            val blue = HttpHeaders.of(mapOf("Content-Type" to listOf("blue"))) { _, _ -> true }

            EqualsVerifier.forClass(AppleReceiptExchangeHttpClientAdapter.Response::class.java)
                .withPrefabValues(HttpHeaders::class.java, red, blue)
                .verify()
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

            val serverResponseClock = Clock.fixed(Instant.parse("2020-11-21T22:16:05.466Z"), ZoneOffset.UTC)
            val date = DateTimeFormatter
                .RFC_1123_DATE_TIME
                .withZone(serverResponseClock.zone)
                .format(serverResponseClock.instant())

            val receiptP7s = javaClass
                .readTextResource("/iOS14-attestation-receipt-response-base64.p7s")
                .toByteArray()
                .inputStream()
                .reader()
                .let(::PEMParser)
                .readObject() as ContentInfo

            val responseBody = receiptP7s.encoded.toBase64()

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
                    privateKeyPem = CertUtils.generateP256KeyPair().private.toPEM(),
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
                creationTime.value shouldBe Instant.parse("2020-11-21T22:16:05.466Z")
                environment?.value shouldBe "sandbox"
                expirationTime.value shouldBe creationTime.value.plus(Duration.ofDays(90))
                notBefore?.value shouldBe creationTime.value.plus(Duration.ofDays(1))
                riskMetric?.value shouldBe 2
                token.value shouldBe "7URCQP4mKgM9qW9M/zxuPweeyX0tvFfN5xTY4u9JYLPlTTfmL126irzJn0l+i4R7gloRfkoNiNixMAqUwW5jIQ=="
                type.value shouldBe Receipt.Type.RECEIPT
            }
        }

        "ReceiptExchange returns same receipt for too early request with MockWebServer" {
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

            val serverResponseClock = Clock.fixed(Instant.parse("2020-11-21T22:32:39.000Z"), ZoneOffset.UTC)
            val date = DateTimeFormatter
                .RFC_1123_DATE_TIME
                .withZone(serverResponseClock.zone)
                .format(serverResponseClock.instant())

            val receiptP7s = javaClass
                .readTextResource("/iOS14-attestation-receipt-response-base64.p7s")
                .toByteArray()
                .inputStream()
                .reader()
                .let(::PEMParser)
                .readObject() as ContentInfo

            val mockResponse = MockResponse().apply {
                setHeader("Server", "Apple")
                setHeader("Date", date)
                setHeader("Content-Length", 0)
                setHeader("Connection", "keep-alive")
                setHeader("X-B3-TraceId", "ae2f84c23e116eb5")
                setHeader("Strict-Transport-Security", "max-age=31536000; includeSubdomains")
                setHeader("X-Frame-Options", "SAMEORIGIN")
                setHeader("X-Content-Type-Options", "nosniff")
                setHeader("X-XSS-Protection", "1; mode=block")

                setResponseCode(304)
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
                    privateKeyPem = CertUtils.generateP256KeyPair().private.toPEM(),
                    clock = serverResponseClock,
                ),
                receiptValidator = appleAppAttest.createReceiptValidator(
                    clock = serverResponseClock,
                ),
                appleDeviceCheckUrl = mockWebServerUri,
            )

            val receipt = receiptExchange.trade(
                receiptP7 = receiptP7s.encoded,
                attestationPublicKey = attestationResponse.publicKey
            )

            mockWebServer.shutdown()

            receipt.p7 shouldBe receiptP7s.encoded
        }

        "ReceiptExchange throws ReceiptExchangeException.HttpError for an unsuccessful call to Apple's servers" {
            // Test setup
            val (attestationResponse, appleAppAttest, attestationClock) = TestUtils.loadValidatedAttestationResponse()

            // Actual test
            val mockWebServer = MockWebServer().apply {
                enqueue(MockResponse().apply { setResponseCode(403) })
                start()
            }

            val receiptExchange = appleAppAttest.createReceiptExchange(
                appleJwsGenerator = AppleJwsGeneratorImpl(
                    teamIdentifier = "WURZELPFRO",
                    keyIdentifier = "WURZELPFRO",
                    privateKeyPem = CertUtils.generateP256KeyPair().private.toPEM(),
                    clock = attestationClock,
                ),
                receiptValidator = appleAppAttest.createReceiptValidator(
                    clock = attestationClock,
                ),
                appleDeviceCheckUrl = mockWebServer.url("/v1/attestationData").toUri(),
            )

            val exception = shouldThrow<ReceiptExchangeException.HttpError> {
                receiptExchange.trade(
                    receiptP7 = attestationResponse.receipt.p7,
                    attestationPublicKey = attestationResponse.publicKey
                )
            }
            mockWebServer.shutdown()

            exception.shouldHaveMessage(
                "Caught an error in Apple's response: Response(statusCode=403, " +
                    "headers=java.net.http.HttpHeaders@bc7b26f5 { {content-length=[0]} }, body=[])"
            )
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
                token.value shouldBe "7URCQP4mKgM9qW9M/zxuPweeyX0tvFfN5xTY4u9JYLPlTTfmL126irzJn0l+i4R7gloRfkoNiNixMAqUwW5jIQ=="
                type.value shouldBe Receipt.Type.RECEIPT
            }
        }
    }
}
