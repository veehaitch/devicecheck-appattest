package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.CertUtils
import ch.veehait.devicecheck.appattest.TestExtensions.copy
import ch.veehait.devicecheck.appattest.TestExtensions.encode
import ch.veehait.devicecheck.appattest.attestation.AttestationValidator
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.util.Extensions.createAppleKeyId
import com.google.common.primitives.Bytes
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldNotThrowAnyUnit
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.throwable.shouldHaveMessage
import io.kotest.property.Exhaustive
import io.kotest.property.checkAll
import io.kotest.property.exhaustive.longs
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.interfaces.ECPublicKey
import java.time.Clock
import java.time.Duration
import java.time.ZoneOffset
import kotlin.experimental.xor

class ReceiptValidatorTest : FreeSpec() {

    init {
        "Accepts valid receipt samples" - {
            ReceiptSample.all.map(::ReceiptSampleBundle).forEach { bundle ->
                "${bundle.sample.properties.type}/${bundle.sample.id}" {
                    val sample = bundle.sample
                    val validatedReceipt = bundle.validator.validateReceipt(
                        receiptP7 = sample.receipt,
                        publicKey = sample.publicKey
                    )

                    with(validatedReceipt.payload) {
                        appId.value shouldBe bundle.appleAppAttest.app.appIdentifier
                        attestationCertificate.value.publicKey shouldBe sample.publicKey
                        attestationCertificate.value.publicKey.createAppleKeyId() shouldBe sample.keyId
                        clientHash.value shouldBe sample.properties.clientHash
                        creationTime.value shouldBe sample.properties.creationTime
                        environment?.value shouldBe sample.properties.environment
                        expirationTime.value shouldBe sample.properties.expirationTime
                        expirationTime.value shouldBe creationTime.value.plus(Duration.ofDays(90))
                        if (notBefore != null) {
                            notBefore!!.value shouldBe sample.properties.notBefore
                            notBefore!!.value shouldBe creationTime.value.plus(Duration.ofDays(1))
                        }
                        riskMetric?.value shouldBe sample.properties.riskMetric
                        token.value shouldBe sample.properties.token
                        type.value shouldBe sample.properties.type
                    }
                }
            }
        }

        "Accepts resigned valid receipt samples" - {
            ReceiptSample.all.map(::ReceiptSampleBundle).forEach { bundle ->
                val fakeEnvironmentValue = "wurzelpfropf"
                "environment=$fakeEnvironmentValue ${bundle.sample.properties.type}/${bundle.sample.id}" {
                    val sample = bundle.sample
                    val validatedReceipt = bundle.validator.validateReceipt(
                        receiptP7 = sample.receipt,
                        publicKey = sample.publicKey
                    )

                    val fakeReceiptBundle = CertUtils.resignReceipt(
                        validatedReceipt,
                        payloadMutator = {
                            val fakeEnvironment = it.environment!!.copy(fakeEnvironmentValue)
                            it.copy(environment = fakeEnvironment)
                        }
                    )

                    val fakeReceiptValidator = bundle.appleAppAttest.createReceiptValidator(
                        trustAnchor = fakeReceiptBundle.trustAnchor,
                        clock = Clock.fixed(sample.timestamp, ZoneOffset.UTC)
                    )

                    val fakeReceipt = shouldNotThrowAny {
                        fakeReceiptValidator.validateReceipt(
                            receiptP7 = fakeReceiptBundle.receipt.p7,
                            publicKey = fakeReceiptBundle.leafCertificate.publicKey as ECPublicKey
                        )
                    }

                    fakeReceipt.payload.environment?.value shouldBe fakeEnvironmentValue
                }
            }
        }

        "Throws InvalidPayload for too old receipt" - {
            ReceiptSample.all.map(::ReceiptSampleBundle).forEach { bundle ->
                val sample = bundle.sample
                "${sample.properties.type}/${sample.id}" - {
                    checkAll(Exhaustive.longs(-1L..1L)) { nanosOffset ->
                        val age = ReceiptValidator.APPLE_RECOMMENDED_MAX_AGE.plusNanos(nanosOffset)
                        val receiptValidator = bundle.appleAppAttest.createReceiptValidator(
                            clock = Clock.fixed(bundle.sample.properties.creationTime.plus(age), ZoneOffset.UTC)
                        )

                        if (nanosOffset <= 0L) {
                            "Accepted for $age" {
                                shouldNotThrowAnyUnit {
                                    receiptValidator.validateReceiptAsync(
                                        receiptP7 = sample.receipt,
                                        publicKey = sample.publicKey
                                    )
                                }
                            }
                        } else {
                            "Rejected for $age" {
                                val exception = shouldThrow<ReceiptException.InvalidPayload> {
                                    receiptValidator.validateReceiptAsync(
                                        receiptP7 = sample.receipt,
                                        publicKey = sample.publicKey
                                    )
                                }
                                val expectedTime = sample.properties.creationTime.plusNanos(nanosOffset)
                                exception.shouldHaveMessage("Receipt's creation time is after $expectedTime")
                            }
                        }
                    }
                }
            }
        }

        "Throws InvalidPayload for wrong app identifier" - {
            ReceiptSample.all.forEach { sample ->
                val app = App("wurzelpfro", "pf")
                "appId=${app.appIdentifier} ${sample.properties.type}/${sample.id}" - {
                    val receiptValidator = AppleAppAttest(
                        app = app,
                        appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
                    ).createReceiptValidator(
                        clock = Clock.fixed(sample.timestamp, ZoneOffset.UTC)
                    )

                    val exception = shouldThrow<ReceiptException.InvalidPayload> {
                        receiptValidator.validateReceiptAsync(
                            receiptP7 = sample.receipt,
                            publicKey = sample.publicKey
                        )
                    }
                    val unexcptedAppId = App(sample.teamIdentifier, sample.bundleIdentifier).appIdentifier
                    exception shouldHaveMessage "Unexpected App ID: $unexcptedAppId"
                }
            }
        }

        "Throws InvalidPayload for wrong public key" - {
            ReceiptSample.all.map(::ReceiptSampleBundle).forEach { bundle ->
                val sample = bundle.sample
                "${sample.properties.type}/${sample.id}" - {
                    val receiptValidator = bundle.appleAppAttest.createReceiptValidator(
                        clock = Clock.fixed(sample.timestamp, ZoneOffset.UTC)
                    )
                    val exception = shouldThrow<ReceiptException.InvalidPayload> {
                        receiptValidator.validateReceiptAsync(
                            receiptP7 = sample.receipt,
                            publicKey = CertUtils.generateP256KeyPair().public as ECPublicKey
                        )
                    }
                    exception shouldHaveMessage "Public key from receipt and attestation statement do not match"
                }
            }
        }

        "Throws InvalidCertificateChain for wrong root CA" - {
            ReceiptSample.all.map(::ReceiptSampleBundle).forEach { bundle ->
                val sample = bundle.sample
                "${sample.properties.type}/${sample.id}" - {
                    val receiptValidator = bundle.appleAppAttest.createReceiptValidator(
                        clock = Clock.fixed(sample.timestamp, ZoneOffset.UTC),
                        // Wrong trust anchor
                        trustAnchor = AttestationValidator.APPLE_APP_ATTEST_ROOT_CA_BUILTIN_TRUST_ANCHOR
                    )
                    val exception = shouldThrow<ReceiptException.InvalidCertificateChain> {
                        receiptValidator.validateReceiptAsync(
                            receiptP7 = sample.receipt,
                            publicKey = sample.publicKey
                        )
                    }
                    exception shouldHaveMessage "The receipt object does not contain a valid certificate chain"
                }
            }
        }

        "Throws InvalidSignature for invalid signature" - {
            ReceiptSample.all.map(::ReceiptSampleBundle).forEach { bundle ->
                val sample = bundle.sample
                "${sample.properties.type}/${sample.id}" - {
                    // Test setup
                    val receiptValidator = bundle.appleAppAttest.createReceiptValidator(
                        clock = Clock.fixed(sample.timestamp, ZoneOffset.UTC)
                    )
                    val receipt = receiptValidator.validateReceiptAsync(
                        receiptP7 = sample.receipt,
                        publicKey = sample.publicKey
                    )

                    // Actual test

                    // Search for the position of the "client hash" field and negate the last byte of the value
                    // to invalidate the signature for this payload
                    val clientHashAsn1 = receipt.payload.clientHash.encode().encoded
                    val clientHashAsn1StartIndex = Bytes.indexOf(receipt.p7, clientHashAsn1)
                    val receiptP7InvalidSignature = receipt.p7.let {
                        val i = clientHashAsn1StartIndex + clientHashAsn1.size - 1
                        it[i] = it[i].xor(1)
                        it
                    }

                    val exception = shouldThrow<ReceiptException.InvalidSignature> {
                        receiptValidator.validateReceiptAsync(
                            receiptP7 = receiptP7InvalidSignature,
                            publicKey = sample.publicKey
                        )
                    }
                    exception shouldHaveMessage "The receipt signature is invalid"
                }
            }
        }

        "Throws InvalidSignature for multiple signers" - {
            ReceiptSample.all.map(::ReceiptSampleBundle).forEach { bundle ->
                val sample = bundle.sample
                "${sample.properties.type}/${sample.id}" - {
                    val validatedReceipt = bundle.validator.validateReceipt(
                        receiptP7 = sample.receipt,
                        publicKey = sample.publicKey
                    )

                    val fakeReceiptBundle = CertUtils.resignReceipt(
                        validatedReceipt,
                        generatorMutator = {
                            val keyPair = CertUtils.generateP256KeyPair()
                            val certBundle = CertUtils.createCertificate(
                                certTemplate = ReceiptValidator.APPLE_PUBLIC_ROOT_CA_G3_BUILTIN_TRUST_ANCHOR.trustedCert
                            )

                            it.addSignerInfoGenerator(
                                JcaSimpleSignerInfoGeneratorBuilder()
                                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                    .build("SHA256withECDSA", keyPair.private, certBundle.certificate)
                            )
                        }
                    )

                    val fakeReceiptValidator = bundle.appleAppAttest.createReceiptValidator(
                        trustAnchor = fakeReceiptBundle.trustAnchor,
                        clock = Clock.fixed(sample.timestamp, ZoneOffset.UTC)
                    )

                    val exception = shouldThrow<ReceiptException.InvalidSignature> {
                        fakeReceiptValidator.validateReceipt(
                            receiptP7 = fakeReceiptBundle.receipt.p7,
                            publicKey = fakeReceiptBundle.leafCertificate.publicKey as ECPublicKey
                        )
                    }
                    exception shouldHaveMessage "The receipt contains more than one signature"
                }
            }
        }
    }
}
