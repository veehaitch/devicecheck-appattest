package ch.veehait.devicecheck.appattest.assertion

import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.TestExtensions.readTextResource
import ch.veehait.devicecheck.appattest.TestUtils
import ch.veehait.devicecheck.appattest.TestUtils.cborObjectMapper
import ch.veehait.devicecheck.appattest.TestUtils.jsonObjectMapper
import ch.veehait.devicecheck.appattest.attestation.AppleAppAttestValidationResponse
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.common.AuthenticatorData
import ch.veehait.devicecheck.appattest.common.AuthenticatorDataFlag
import ch.veehait.devicecheck.appattest.util.Extensions.toBase64
import com.fasterxml.jackson.module.kotlin.readValue
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.ints.shouldBeExactly
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.throwable.shouldHaveMessage
import nl.jqno.equalsverifier.EqualsVerifier
import org.bouncycastle.util.Arrays
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.time.Clock
import kotlin.experimental.and

class AssertionValidatorTest : StringSpec() {
    private fun attest(): Triple<AppleAppAttestValidationResponse, App, Clock> {
        val (attestationSample, app, clock) = TestUtils.loadValidAttestationSample()
        val appleAppAttest = AppleAppAttest(
            app = app,
            appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
        )
        val attestationValidator = appleAppAttest.createAttestationValidator(
            clock = clock,
            receiptValidator = appleAppAttest.createReceiptValidator(
                clock = clock,
            ),
        )
        val attestationResponse = attestationValidator.validate(
            attestationObject = attestationSample.attestation,
            keyIdBase64 = attestationSample.keyId.toBase64(),
            serverChallenge = attestationSample.clientData
        )
        return Triple(attestationResponse, app, clock)
    }

    private val assertionChallengeAlwaysAcceptedValidator = object : AssertionChallengeValidator {
        override fun validate(
            assertionObj: Assertion,
            clientData: ByteArray,
            attestationPublicKey: ECPublicKey,
            challenge: ByteArray,
        ): Boolean {
            return true
        }
    }

    init {
        "Assertion: equals/hashCode" {
            EqualsVerifier.forClass(Assertion::class.java).verify()
        }

        "AssertionEnvelope: equals/hashCode" {
            EqualsVerifier.forClass(AssertionEnvelope::class.java).verify()
        }

        "Assertion authenticator data claims attested credentials but does not include any" {
            val assertionSampleJson = javaClass.readTextResource("/iOS14-assertion-sample.json")
            val assertionSample: AssertionSample = jsonObjectMapper.readValue(assertionSampleJson)

            val assertionObject: AssertionEnvelope = cborObjectMapper.readValue(assertionSample.assertion)
            val flagsByte = assertionObject.authenticatorData[AuthenticatorData.FLAGS_INDEX]

            flagsByte.and(AuthenticatorDataFlag.AT.bitmask).toInt() shouldNotBe 0
            assertionObject.authenticatorData.size shouldBeExactly 37
        }

        "Validating an assertion works" {
            val (attestationResponse, app, _) = attest()
            val assertionSampleJson = javaClass.readTextResource("/iOS14-assertion-sample.json")
            val assertionSample: AssertionSample = jsonObjectMapper.readValue(assertionSampleJson)

            val assertionChallengeValidator = object : AssertionChallengeValidator {
                override fun validate(
                    assertionObj: Assertion,
                    clientData: ByteArray,
                    attestationPublicKey: ECPublicKey,
                    challenge: ByteArray,
                ): Boolean {
                    return Arrays.constantTimeAreEqual("wurzel".toByteArray(), challenge)
                }
            }
            val assertionValidator = AppleAppAttest(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            ).createAssertionValidator(assertionChallengeValidator)

            val assertion = assertionValidator.validate(
                assertionObject = assertionSample.assertion,
                clientData = assertionSample.clientData,
                attestationPublicKey = attestationResponse.publicKey,
                lastCounter = 0L,
                challenge = assertionSample.challenge,
            )

            assertion.authenticatorData.signCount shouldBe 1L
        }

        "Throws InvalidChallenge for invalid challenge" {
            val (attestationResponse, app, _) = attest()
            val assertionSampleJson = javaClass.readTextResource("/iOS14-assertion-sample.json")
            val assertionSample: AssertionSample = jsonObjectMapper.readValue(assertionSampleJson)

            val assertionChallengeValidator = object : AssertionChallengeValidator {
                override fun validate(
                    assertionObj: Assertion,
                    clientData: ByteArray,
                    attestationPublicKey: ECPublicKey,
                    challenge: ByteArray,
                ): Boolean {
                    return false
                }
            }
            val assertionValidator = AppleAppAttest(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            ).createAssertionValidator(assertionChallengeValidator)

            shouldThrow<AssertionException.InvalidChallenge> {
                assertionValidator.validate(
                    assertionObject = assertionSample.assertion,
                    clientData = assertionSample.clientData,
                    attestationPublicKey = attestationResponse.publicKey,
                    lastCounter = 0L,
                    challenge = assertionSample.challenge,
                )
            }
        }

        "Throws InvalidAuthenticatorData for invalid app ID" {
            val (attestationResponse, app, _) = attest()
            val assertionSampleJson = javaClass.readTextResource("/iOS14-assertion-sample.json")
            val assertionSample: AssertionSample = jsonObjectMapper.readValue(assertionSampleJson)

            val wrongBundleId = "fporfplezruw"
            val assertionValidator = AppleAppAttest(
                app = app.copy(bundleIdentifier = wrongBundleId),
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            ).createAssertionValidator(assertionChallengeAlwaysAcceptedValidator)

            val exception = shouldThrow<AssertionException.InvalidAuthenticatorData> {
                assertionValidator.validate(
                    assertionObject = assertionSample.assertion,
                    clientData = assertionSample.clientData,
                    attestationPublicKey = attestationResponse.publicKey,
                    lastCounter = 0L,
                    challenge = assertionSample.challenge,
                )
            }
            exception shouldHaveMessage "App ID hash does not match RP ID hash"
        }

        "Throws InvalidAuthenticatorData for invalid counter value" {
            val (attestationResponse, app, _) = attest()
            val assertionSampleJson = javaClass.readTextResource("/iOS14-assertion-sample.json")
            val assertionSample: AssertionSample = jsonObjectMapper.readValue(assertionSampleJson)

            val assertionValidator = AppleAppAttest(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            ).createAssertionValidator(assertionChallengeAlwaysAcceptedValidator)
            val wrongCounterValue = Long.MAX_VALUE

            val exception = shouldThrow<AssertionException.InvalidAuthenticatorData> {
                assertionValidator.validate(
                    assertionObject = assertionSample.assertion,
                    clientData = assertionSample.clientData,
                    attestationPublicKey = attestationResponse.publicKey,
                    lastCounter = wrongCounterValue,
                    challenge = assertionSample.challenge,
                )
            }
            exception shouldHaveMessage "Assertion counter is not greater than the counter saved counter"
        }

        "Throws InvalidSignature for invalid signature" {
            val (attestationResponse, app, _) = attest()
            val assertionSampleJson = javaClass.readTextResource("/iOS14-assertion-sample.json")
            val assertionSample: AssertionSample = jsonObjectMapper.readValue(assertionSampleJson)

            val assertionValidator = AppleAppAttest(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            ).createAssertionValidator(assertionChallengeAlwaysAcceptedValidator)
            val wrongClientData = "fporfplezruw".toByteArray()

            shouldThrow<AssertionException.InvalidSignature> {
                assertionValidator.validate(
                    assertionObject = assertionSample.assertion,
                    clientData = wrongClientData,
                    attestationPublicKey = attestationResponse.publicKey,
                    lastCounter = 0L,
                    challenge = assertionSample.challenge,
                )
            }
        }

        "Throws InvalidSignature for malformatted signature" {
            val (attestationResponse, app, _) = attest()
            val assertionSampleJson = javaClass.readTextResource("/iOS14-assertion-sample.json")
            val assertionSample: AssertionSample = jsonObjectMapper.readValue(assertionSampleJson)

            val assertionValidator = AppleAppAttest(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
            ).createAssertionValidator(assertionChallengeAlwaysAcceptedValidator)
            val assertionEnvelope: AssertionEnvelope = cborObjectMapper.readValue(assertionSample.assertion)
            val assertionObjectTampered = assertionEnvelope.copy(
                signature = ByteArray(assertionEnvelope.signature.size).apply {
                    SecureRandom().nextBytes(this)
                }
            )
            val assertionTampered = cborObjectMapper.writeValueAsBytes(assertionObjectTampered)

            shouldThrow<AssertionException.InvalidSignature> {
                assertionValidator.validate(
                    assertionObject = assertionTampered,
                    clientData = assertionSample.clientData,
                    attestationPublicKey = attestationResponse.publicKey,
                    lastCounter = 0L,
                    challenge = assertionSample.challenge,
                )
            }
        }
    }
}
