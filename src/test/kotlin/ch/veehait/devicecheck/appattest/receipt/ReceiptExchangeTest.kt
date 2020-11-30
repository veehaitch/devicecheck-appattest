package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.CertUtils
import ch.veehait.devicecheck.appattest.CertUtils.toPEM
import ch.veehait.devicecheck.appattest.TestExtensions.fixedUtcClock
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.common.EqualsVerifierPrefabValues
import ch.veehait.devicecheck.appattest.util.Extensions.createAppleKeyId
import ch.veehait.devicecheck.appattest.util.Extensions.fromBase64
import ch.veehait.devicecheck.appattest.util.Extensions.toBase64
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.comparables.shouldBeGreaterThan
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.ints.shouldBeGreaterThanOrEqual
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.throwable.shouldHaveMessage
import io.kotest.property.Exhaustive
import io.kotest.property.checkAll
import io.kotest.property.exhaustive.longs
import nl.jqno.equalsverifier.EqualsVerifier
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import java.net.HttpURLConnection
import java.net.URI
import java.net.http.HttpHeaders
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class ReceiptExchangeTest : FreeSpec() {

    private val nullAppleJwsGenerator = object : AppleJwsGenerator {
        override val teamIdentifier = ""
        override val keyIdentifier = ""
        override val privateKey = CertUtils.generateP256KeyPair().private
        override fun issueToken() = ""
    }

    init {
        "AppleReceiptHttpClientAdapter.Response: equals/hashCode" {
            EqualsVerifier.forClass(AppleReceiptExchangeHttpClientAdapter.Response::class.java)
                .withPrefabValues(
                    HttpHeaders::class.java,
                    EqualsVerifierPrefabValues.HttpHeaders.red,
                    EqualsVerifierPrefabValues.HttpHeaders.blue,
                )
                .verify()
        }

        "Has correct constant for Apple's development server endpoint" {
            // Use the base URL of https://data-development.appattest.apple.com shown in the example above for testing.
            with(ReceiptExchange) {
                APPLE_DEVICE_CHECK_APP_ATTEST_DEVELOPMENT_URL.toString() shouldBe
                    "https://data-development.appattest.apple.com/v1/attestationData"
                APPLE_DEVICE_CHECK_APP_ATTEST_DEVELOPMENT_URL shouldNotBe APPLE_DEVICE_CHECK_APP_ATTEST_PRODUCTION_URL
            }
        }

        "Has correct constant for Apple's production server endpoint" {
            // To work with apps that you’ve distributed through the App Store, TestFlight, or with an Enterprise
            // Developer certificate, use a base URL of https://data.appattest.apple.com instead.
            with(ReceiptExchange) {
                APPLE_DEVICE_CHECK_APP_ATTEST_PRODUCTION_URL.toString() shouldBe
                    "https://data.appattest.apple.com/v1/attestationData"
                APPLE_DEVICE_CHECK_APP_ATTEST_PRODUCTION_URL shouldNotBe APPLE_DEVICE_CHECK_APP_ATTEST_DEVELOPMENT_URL
            }
        }

        "ReceiptExchange works with MockWebServer" {
            val receiptSamples: List<ReceiptSample> = ReceiptSample.all

            val attestationReceipt = receiptSamples.first { it.properties.type == Receipt.Type.ATTEST }
            val responseReceipt = receiptSamples.first { it.properties.type == Receipt.Type.RECEIPT }

            val appleAppAttest = AppleAppAttest(
                app = App(attestationReceipt.teamIdentifier, attestationReceipt.bundleIdentifier),
                appleAppAttestEnvironment = attestationReceipt.environment,
            )

            val serverResponseClock = Clock.fixed(responseReceipt.timestamp, ZoneOffset.UTC)
            val date = DateTimeFormatter
                .RFC_1123_DATE_TIME
                .withZone(serverResponseClock.zone)
                .format(serverResponseClock.instant())

            val responseBody = responseReceipt.receipt.toBase64()

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

                setResponseCode(HttpURLConnection.HTTP_OK)
                setBody(responseBody)
            }

            val mockWebServer = MockWebServer().apply {
                enqueue(mockResponse)
                start()
            }

            val appleServerUrl = when (attestationReceipt.environment) {
                AppleAppAttestEnvironment.DEVELOPMENT -> ReceiptExchange.APPLE_DEVICE_CHECK_APP_ATTEST_DEVELOPMENT_URL
                AppleAppAttestEnvironment.PRODUCTION -> ReceiptExchange.APPLE_DEVICE_CHECK_APP_ATTEST_PRODUCTION_URL
            }
            val mockWebServerUri = mockWebServer.url(appleServerUrl.path).toUri()

            // Actual test
            val receiptExchange = appleAppAttest.createReceiptExchange(
                appleJwsGenerator = AppleJwsGeneratorImpl(
                    teamIdentifier = attestationReceipt.teamIdentifier,
                    keyIdentifier = "WURZELPFRO",
                    privateKeyPem = CertUtils.generateP256KeyPair().private.toPEM(),
                    clock = serverResponseClock,
                ),
                receiptValidator = appleAppAttest.createReceiptValidator(
                    clock = serverResponseClock,
                ),
                appleDeviceCheckUrl = mockWebServerUri,
                appleReceiptExchangeHttpClientAdapter = SimpleAppleReceiptExchangeHttpClientAdapter(),
            )

            val receipt = receiptExchange.trade(
                receiptP7 = attestationReceipt.receipt,
                attestationPublicKey = attestationReceipt.publicKey
            )

            mockWebServer.shutdown()

            receipt.p7 shouldBe mockResponse.getBody()!!.readByteArray().fromBase64()
        }

        "ReceiptExchange returns same receipt for too early request with MockWebServer" {
            val receiptSamples: List<ReceiptSample> = ReceiptSample.all

            val responseReceipt = receiptSamples.first { it.properties.type == Receipt.Type.RECEIPT }

            val appleAppAttest = AppleAppAttest(
                app = App(responseReceipt.teamIdentifier, responseReceipt.bundleIdentifier),
                appleAppAttestEnvironment = responseReceipt.environment,
            )

            val serverResponseClock = Clock.fixed(responseReceipt.timestamp, ZoneOffset.UTC)
            val date = DateTimeFormatter
                .RFC_1123_DATE_TIME
                .withZone(serverResponseClock.zone)
                .format(serverResponseClock.instant())

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

                setResponseCode(HttpURLConnection.HTTP_NOT_MODIFIED)
            }

            val mockWebServer = MockWebServer().apply {
                enqueue(mockResponse)
                start()
            }

            val appleServerUrl = when (responseReceipt.environment) {
                AppleAppAttestEnvironment.DEVELOPMENT -> ReceiptExchange.APPLE_DEVICE_CHECK_APP_ATTEST_DEVELOPMENT_URL
                AppleAppAttestEnvironment.PRODUCTION -> ReceiptExchange.APPLE_DEVICE_CHECK_APP_ATTEST_PRODUCTION_URL
            }
            val mockWebServerUri = mockWebServer.url(appleServerUrl.path).toUri()

            // Actual test
            val receiptExchange = appleAppAttest.createReceiptExchange(
                appleJwsGenerator = nullAppleJwsGenerator,
                receiptValidator = appleAppAttest.createReceiptValidator(
                    clock = serverResponseClock,
                ),
                appleDeviceCheckUrl = mockWebServerUri,
                appleReceiptExchangeHttpClientAdapter = SimpleAppleReceiptExchangeHttpClientAdapter(),
                sanityChecks = false,
            )

            val receipt = receiptExchange.trade(
                receiptP7 = responseReceipt.receipt,
                attestationPublicKey = responseReceipt.publicKey
            )

            mockWebServer.shutdown()

            receipt.p7 shouldBe responseReceipt.receipt
        }

        "ReceiptExchange throws ReceiptExchangeException.HttpError for an unsuccessful call to Apple's servers" {
            // Test setup
            val sample = ReceiptSample.all.random()
            val appleAppAttest = sample.defaultAppleAppAttest()

            // Actual test
            val mockWebServer = MockWebServer().apply {
                enqueue(MockResponse().apply { setResponseCode(403) })
                start()
            }

            val receiptExchange = appleAppAttest.createReceiptExchange(
                appleJwsGenerator = nullAppleJwsGenerator,
                receiptValidator = appleAppAttest.createReceiptValidator(
                    clock = sample.timestamp.fixedUtcClock(),
                ),
                appleDeviceCheckUrl = mockWebServer.url("/v1/attestationData").toUri(),
                sanityChecks = false,
            )

            val exception = shouldThrow<ReceiptExchangeException.HttpError> {
                receiptExchange.trade(
                    receiptP7 = sample.receipt,
                    attestationPublicKey = sample.publicKey
                )
            }
            mockWebServer.shutdown()

            exception.shouldHaveMessage(
                "Caught an error in Apple's response: Response(statusCode=403, " +
                    "headers=java.net.http.HttpHeaders@bc7b26f5 { {content-length=[0]} }, body=[])"
            )
        }

        "Throws ReceiptExpired for a receipt which is too old" - {
            val sample = ReceiptSample.all.random()
            val appleAppAttest = sample.defaultAppleAppAttest()
            val receipt = appleAppAttest.createReceiptValidator(
                clock = sample.timestamp.fixedUtcClock(),
            ).validateReceipt(
                receiptP7 = sample.receipt,
                publicKey = sample.publicKey,
            )

            checkAll(Exhaustive.longs(-1L..1L)) { nanosOffset ->
                val receiptExchange = appleAppAttest.createReceiptExchange(
                    appleJwsGenerator = nullAppleJwsGenerator,
                    receiptValidator = appleAppAttest.createReceiptValidator(
                        clock = receipt.payload.expirationTime.value.plusNanos(nanosOffset).fixedUtcClock(),
                    ),
                    appleReceiptExchangeHttpClientAdapter = object : AppleReceiptExchangeHttpClientAdapter {
                        override fun post(uri: URI, authorizationHeader: Map<String, String>, body: ByteArray): AppleReceiptExchangeHttpClientAdapter.Response {
                            throw IllegalAccessError("wurzelpfropf")
                        }
                    },
                    sanityChecks = true,
                )

                if (nanosOffset < 0L) {
                    "Accepts offset of ${nanosOffset}ns to expiry date" {
                        val exception = shouldThrow<IllegalAccessError> {
                            receiptExchange.trade(
                                receiptP7 = sample.receipt,
                                attestationPublicKey = sample.publicKey,
                            )
                        }
                        exception.shouldHaveMessage("wurzelpfropf")
                    }
                } else {
                    "Rejects offset of ${nanosOffset}ns to expiry date" {
                        shouldThrow<ReceiptExchangeException.ReceiptExpired> {
                            receiptExchange.trade(
                                receiptP7 = sample.receipt,
                                attestationPublicKey = sample.publicKey,
                            )
                        }
                    }
                }
            }
        }

        "Returns same receipt for too early call" - {
            ReceiptSample.all.forEach { sample ->
                val appleAppAttest = sample.defaultAppleAppAttest()
                val receipt = appleAppAttest.createReceiptValidator(
                    clock = sample.timestamp.fixedUtcClock(),
                ).validateReceipt(
                    receiptP7 = sample.receipt,
                    publicKey = sample.publicKey,
                )
                val receiptType = receipt.payload.type.value

                "$receiptType/${sample.id}" - {
                    checkAll(Exhaustive.longs(-1L..1L)) { nanosOffset ->
                        val receiptExchange = appleAppAttest.createReceiptExchange(
                            appleJwsGenerator = nullAppleJwsGenerator,
                            receiptValidator = appleAppAttest.createReceiptValidator(
                                clock = when (receiptType) {
                                    Receipt.Type.RECEIPT -> receipt.payload.notBefore!!.value.plusNanos(nanosOffset).fixedUtcClock()
                                    Receipt.Type.ATTEST -> receipt.payload.creationTime.value.fixedUtcClock()
                                }
                            ),
                            appleReceiptExchangeHttpClientAdapter = object : AppleReceiptExchangeHttpClientAdapter {
                                override fun post(uri: URI, authorizationHeader: Map<String, String>, body: ByteArray): AppleReceiptExchangeHttpClientAdapter.Response {
                                    throw IllegalAccessError("wurzelpfropf")
                                }
                            },
                            sanityChecks = true,
                        )

                        if (receiptType == Receipt.Type.RECEIPT && nanosOffset < 0L) {
                            "validty offset ${nanosOffset}ns: No remote call" {
                                val receiptNew = shouldNotThrowAny {
                                    receiptExchange.trade(
                                        receiptP7 = sample.receipt,
                                        attestationPublicKey = sample.publicKey,
                                    )
                                }
                                receiptNew.p7 shouldBe sample.receipt
                            }
                        } else {
                            "validty offset ${nanosOffset}ns: Remote call" {
                                val exception = shouldThrow<IllegalAccessError> {
                                    receiptExchange.trade(
                                        receiptP7 = sample.receipt,
                                        attestationPublicKey = sample.publicKey,
                                    )
                                }
                                exception.shouldHaveMessage("wurzelpfropf")
                            }
                        }
                    }
                }
            }
        }

        val appleDeviceCheckKid = "94M3Z58NQ7"
        val appleDeviceCheckPrivateKeyPem = System.getenv("APPLE_KEY_P8_$appleDeviceCheckKid")

        "receipt exchange works".config(enabled = appleDeviceCheckPrivateKeyPem != null) {
            // Test setup
            val sample = ReceiptSample.all.maxByOrNull { it.timestamp }!!
            val appleAppAttest = sample.defaultAppleAppAttest()

            // Actual test
            val receiptExchange = appleAppAttest.createReceiptExchange(
                appleJwsGenerator = AppleJwsGeneratorImpl(
                    teamIdentifier = sample.teamIdentifier,
                    keyIdentifier = appleDeviceCheckKid,
                    privateKeyPem = appleDeviceCheckPrivateKeyPem
                ),
                receiptValidator = appleAppAttest.createReceiptValidator(),
            )

            val receipt = receiptExchange.trade(
                receiptP7 = sample.receipt,
                attestationPublicKey = sample.publicKey
            )

            if (!sample.receipt.contentEquals(receipt.p7)) {
                with(receipt.payload) {
                    appId.value shouldBe appleAppAttest.app.appIdentifier
                    attestationCertificate.value.publicKey shouldBe sample.publicKey
                    attestationCertificate.value.publicKey.createAppleKeyId() shouldBe sample.keyId
                    clientHash.value shouldBe sample.properties.clientHash
                    creationTime.value shouldBeGreaterThan Instant.now().minus(Duration.ofMinutes(5))
                    creationTime.value shouldBeLessThan Instant.now().plus(Duration.ofMinutes(5))
                    environment?.value shouldBe sample.properties.environment
                    expirationTime.value shouldBe creationTime.value.plus(Duration.ofDays(90))
                    if (notBefore != null) {
                        notBefore!!.value shouldBe creationTime.value.plus(Duration.ofDays(1))
                    }
                    riskMetric!!.value shouldBeGreaterThanOrEqual (sample.properties.riskMetric ?: 0)
                    type.value shouldBe Receipt.Type.RECEIPT
                }
            }
        }
    }
}
