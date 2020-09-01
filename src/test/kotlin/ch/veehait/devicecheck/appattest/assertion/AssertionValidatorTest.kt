package ch.veehait.devicecheck.appattest.assertion

import ch.veehait.devicecheck.appattest.Extensions.toBase64
import ch.veehait.devicecheck.appattest.TestExtensions.readTextResource
import ch.veehait.devicecheck.appattest.TestUtils
import ch.veehait.devicecheck.appattest.TestUtils.jsonObjectMapper
import ch.veehait.devicecheck.appattest.attestation.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.attestation.AttestationValidator
import ch.veehait.devicecheck.appattest.attestation.AttestationValidatorImpl
import com.fasterxml.jackson.module.kotlin.readValue
import io.kotest.core.spec.style.StringSpec
import org.bouncycastle.util.Arrays
import java.security.interfaces.ECPublicKey

class AssertionValidatorTest : StringSpec() {
    init {
        "Validating an assertion works" {
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

            val assertionValidator = AssertionValidatorImpl(
                app = app,
                assertionChallengeValidator = assertionChallengeValidator,
            )
            assertionValidator.validate(
                assertion = assertionSample.assertion,
                clientData = assertionSample.clientData,
                attestationPublicKey = attestationResponse.publicKey,
                lastCounter = 0L,
                challenge = assertionSample.challenge,
            )
        }
    }
}
