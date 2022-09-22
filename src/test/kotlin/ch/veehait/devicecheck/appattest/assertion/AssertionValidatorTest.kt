package ch.veehait.devicecheck.appattest.assertion

import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.CertUtils
import ch.veehait.devicecheck.appattest.TestUtils.cborObjectMapper
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.common.AuthenticatorData
import ch.veehait.devicecheck.appattest.common.AuthenticatorDataFlag
import ch.veehait.devicecheck.appattest.util.Extensions.sha256
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.ints.shouldBeExactly
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.throwable.shouldHaveMessage
import nl.jqno.equalsverifier.EqualsVerifier
import org.bouncycastle.util.Arrays
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import kotlin.experimental.and

class AssertionValidatorTest : FreeSpec() {

    private val assertionChallengeAlwaysAcceptedValidator = object : AssertionChallengeValidator {
        override fun validate(
            assertionObj: Assertion,
            clientData: ByteArray,
            attestationPublicKey: ECPublicKey,
            challenge: ByteArray
        ): Boolean {
            return true
        }
    }

    private fun AssertionSample.challengeAcceptingAssertionValidator() =
        this.defaultAppleAppAttest().createAssertionValidator(
            assertionChallengeAlwaysAcceptedValidator
        )

    init {
        "equals/hashCode" - {
            "Assertion" {
                EqualsVerifier.forClass(Assertion::class.java).verify()
            }

            "AssertionEnvelope" {
                EqualsVerifier.forClass(AssertionEnvelope::class.java).verify()
            }
        }

        "Accepts valid assertion samples" - {
            val objectReader = cborObjectMapper.readerFor(LinkedHashMap::class.java)
            AssertionSample.all.forEach { sample ->
                val decodedAssertion = objectReader.readValue<LinkedHashMap<Any, Any>>(sample.assertion)
                "${sample.id}" {
                    val appleAppAttest = sample.defaultAppleAppAttest()
                    val assertionChallengeValidator = object : AssertionChallengeValidator {
                        override fun validate(
                            assertionObj: Assertion,
                            clientData: ByteArray,
                            attestationPublicKey: ECPublicKey,
                            challenge: ByteArray
                        ): Boolean {
                            return Arrays.constantTimeAreEqual("wurzel".toByteArray(), challenge)
                        }
                    }
                    val assertionValidator = appleAppAttest.createAssertionValidator(assertionChallengeValidator)

                    val assertion = assertionValidator.validate(
                        assertionObject = sample.assertion,
                        clientData = sample.clientData,
                        attestationPublicKey = sample.publicKey,
                        lastCounter = sample.counter - 1,
                        challenge = sample.challenge
                    )

                    assertion.authenticatorData.rpIdHash shouldBe appleAppAttest.app.appIdentifier.toByteArray()
                        .sha256()
                    assertion.authenticatorData.signCount shouldBe 1L

                    assertion.signature shouldBe decodedAssertion["signature"]
                }
            }
        }

        "Assertion authenticator data claims attested credentials but does not include any" - {
            val objectReader = cborObjectMapper.readerFor(AssertionEnvelope::class.java)
            AssertionSample.all.forEach { sample ->
                "${sample.id}" {
                    val assertionObject: AssertionEnvelope = objectReader.readValue(sample.assertion)
                    val flagsByte = assertionObject.authenticatorData[AuthenticatorData.FLAGS_INDEX]

                    flagsByte.and(AuthenticatorDataFlag.AT.bitmask).toInt() shouldNotBe 0
                    assertionObject.authenticatorData.size shouldBeExactly 37
                }
            }
        }

        "Throws InvalidChallenge for invalid challenge" - {
            AssertionSample.all.forEach { sample ->
                "${sample.id}" {
                    val appleAppAttest = sample.defaultAppleAppAttest()

                    val assertionChallengeValidator = object : AssertionChallengeValidator {
                        override fun validate(
                            assertionObj: Assertion,
                            clientData: ByteArray,
                            attestationPublicKey: ECPublicKey,
                            challenge: ByteArray
                        ): Boolean {
                            return false
                        }
                    }
                    val assertionValidator = appleAppAttest.createAssertionValidator(assertionChallengeValidator)

                    shouldThrow<AssertionException.InvalidChallenge> {
                        assertionValidator.validateAsync(
                            assertionObject = sample.assertion,
                            clientData = sample.clientData,
                            attestationPublicKey = sample.publicKey,
                            lastCounter = sample.counter - 1,
                            challenge = sample.challenge
                        )
                    }
                }
            }
        }

        "Throws InvalidAuthenticatorData for AuthenticatorData parsing error" - {
            val objectReader = cborObjectMapper.readerFor(AssertionEnvelope::class.java)
            val objectWriter = cborObjectMapper.writerFor(AssertionEnvelope::class.java)

            AssertionSample.all.forEach { sample ->
                "${sample.id}" {
                    val assertionValidator = sample.challengeAcceptingAssertionValidator()
                    val envelope = objectReader.readValue<AssertionEnvelope>(sample.assertion)
                    val modifiedAuthenticatorData = envelope.authenticatorData.dropLast(1).toByteArray()
                    val keyPair = CertUtils.generateP256KeyPair()
                    val signature = Signature.getInstance(AssertionValidator.SIGNATURE_ALGORITHM).apply {
                        initSign(keyPair.private)
                        val nonce = modifiedAuthenticatorData.plus(sample.clientData.sha256()).sha256()
                        update(nonce)
                    }

                    val modifiedEnvelope = envelope.copy(
                        authenticatorData = envelope.authenticatorData.dropLast(1).toByteArray(),
                        signature = signature.sign()
                    )
                    val modifiedAssertion = objectWriter.writeValueAsBytes(modifiedEnvelope)

                    val exception = shouldThrow<AssertionException.InvalidAuthenticatorData> {
                        assertionValidator.validateAsync(
                            assertionObject = modifiedAssertion,
                            clientData = sample.clientData,
                            attestationPublicKey = keyPair.public as ECPublicKey,
                            lastCounter = sample.counter,
                            challenge = sample.challenge
                        )
                    }
                    exception shouldHaveMessage "Could not parse assertion authenticatorData"
                }
            }
        }

        "Throws InvalidAuthenticatorData for invalid app ID" - {
            AssertionSample.all.forEach { sample ->
                "${sample.id}" {
                    val assertionValidator = AppleAppAttest(
                        app = App(sample.teamIdentifier, sample.bundleIdentifier.reversed()),
                        appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
                    ).createAssertionValidator(assertionChallengeAlwaysAcceptedValidator)

                    val exception = shouldThrow<AssertionException.InvalidAuthenticatorData> {
                        assertionValidator.validateAsync(
                            assertionObject = sample.assertion,
                            clientData = sample.clientData,
                            attestationPublicKey = sample.publicKey,
                            lastCounter = sample.counter - 1,
                            challenge = sample.challenge
                        )
                    }
                    exception shouldHaveMessage "App ID hash does not match RP ID hash"
                }
            }
        }

        "Throws InvalidAuthenticatorData for invalid counter value" - {
            AssertionSample.all.forEach { sample ->
                "${sample.id}" {
                    val assertionValidator = sample.challengeAcceptingAssertionValidator()

                    val exception = shouldThrow<AssertionException.InvalidAuthenticatorData> {
                        assertionValidator.validateAsync(
                            assertionObject = sample.assertion,
                            clientData = sample.clientData,
                            attestationPublicKey = sample.publicKey,
                            lastCounter = sample.counter,
                            challenge = sample.challenge
                        )
                    }
                    exception shouldHaveMessage "Assertion counter is not greater than the counter saved counter"
                }
            }
        }

        "Throws InvalidSignature for invalid signature" - {
            AssertionSample.all.forEach { sample ->
                "${sample.id}" {
                    val assertionValidator = sample.challengeAcceptingAssertionValidator()

                    val wrongClientData = "fporfplezruw".toByteArray()
                    shouldThrow<AssertionException.InvalidSignature> {
                        assertionValidator.validateAsync(
                            assertionObject = sample.assertion,
                            clientData = wrongClientData,
                            attestationPublicKey = sample.publicKey,
                            lastCounter = sample.counter - 1,
                            challenge = sample.challenge
                        )
                    }
                }
            }
        }

        "Throws InvalidSignature for malformatted signature" - {
            val objectReader = cborObjectMapper.readerFor(AssertionEnvelope::class.java)
            val objectWriter = cborObjectMapper.writerFor(AssertionEnvelope::class.java)

            AssertionSample.all.forEach { sample ->
                "${sample.id}" {
                    val assertionValidator = sample.challengeAcceptingAssertionValidator()

                    val assertionEnvelope: AssertionEnvelope = objectReader.readValue(sample.assertion)
                    val assertionObjectTampered = assertionEnvelope.copy(
                        signature = ByteArray(assertionEnvelope.signature.size).apply {
                            SecureRandom().nextBytes(this)
                        }
                    )
                    val assertionTampered = objectWriter.writeValueAsBytes(assertionObjectTampered)

                    shouldThrow<AssertionException.InvalidSignature> {
                        assertionValidator.validateAsync(
                            assertionObject = assertionTampered,
                            clientData = sample.clientData,
                            attestationPublicKey = sample.publicKey,
                            lastCounter = sample.counter - 1,
                            challenge = sample.challenge
                        )
                    }
                }
            }
        }
    }
}
