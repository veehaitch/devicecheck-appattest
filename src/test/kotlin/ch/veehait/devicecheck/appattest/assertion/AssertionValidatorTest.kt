package ch.veehait.devicecheck.appattest.assertion

import ch.veehait.devicecheck.appattest.Extensions.toBase64
import ch.veehait.devicecheck.appattest.attestation.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.attestation.AttestationSample
import ch.veehait.devicecheck.appattest.attestation.AttestationValidator
import ch.veehait.devicecheck.appattest.readTextResource
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.readValue
import io.kotest.core.spec.style.StringSpec
import org.bouncycastle.util.Arrays
import java.security.interfaces.ECPublicKey
import java.time.Clock
import java.time.ZoneOffset

class AssertionValidatorTest : StringSpec() {
    init {
        val jsonObjectMapper = ObjectMapper(JsonFactory())
            .registerModule(JavaTimeModule())
            .registerModule(KotlinModule())

        "Validating an assertion works" {
            val attestationSampleJson = javaClass.readTextResource("/iOS14-attestation-sample.json")
            val attestationSample: AttestationSample = jsonObjectMapper.readValue(attestationSampleJson)

            val attestationResponse = AttestationValidator(
                appTeamIdentifier = attestationSample.teamIdentifier,
                appBundleIdentifier = attestationSample.bundleIdentifier,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT,
                clock = Clock.fixed(attestationSample.timestamp.plusSeconds(5), ZoneOffset.UTC)
            ).validate(
                attestationObject = attestationSample.attestation,
                keyIdBase64 = attestationSample.keyId.toBase64(),
                serverChallenge = attestationSample.clientData
            )

            val assertionSampleJson = javaClass.readTextResource("/iOS14-assertion-sample.json")
            val assertionSample: AssertionSample = jsonObjectMapper.readValue(assertionSampleJson)

            val assertionValidator = AssertionValidatorImpl(
                appTeamIdentifier = assertionSample.teamIdentifier,
                appBundleIdentifier = assertionSample.bundleIdentifier,
            )

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

            assertionValidator.validate(
                assertion = assertionSample.assertion,
                clientData = assertionSample.clientData,
                attestationPublicKey = attestationResponse.publicKey,
                lastCounter = 0L,
                challenge = assertionSample.challenge,
                assertionChallengeValidator = assertionChallengeValidator,
            )
        }
    }
}
