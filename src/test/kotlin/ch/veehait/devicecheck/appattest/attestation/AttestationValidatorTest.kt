package ch.veehait.devicecheck.appattest.attestation

import ch.veehait.devicecheck.appattest.Extensions.toBase64
import ch.veehait.devicecheck.appattest.readTextResource
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.readValue
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class AttestationValidatorTest : StringSpec() {
    init {
        val jsonObjectMapper = ObjectMapper(JsonFactory())
            .registerModule(JavaTimeModule())
            .registerModule(KotlinModule())

        val fixedClock = Clock.fixed(Instant.parse("2020-08-23T11:03:36.059Z"), ZoneOffset.UTC)

        "team identifier must consist of 10 characters" {
            shouldThrow<IllegalArgumentException> {
                AttestationValidator(
                    "a".repeat(9), "",
                    AppleAppAttestEnvironment.DEVELOPMENT, clock = fixedClock
                )
            }
            shouldThrow<IllegalArgumentException> {
                AttestationValidator(
                    "a".repeat(11), "",
                    AppleAppAttestEnvironment.DEVELOPMENT, clock = fixedClock
                )
            }
            AttestationValidator(
                "a".repeat(10), "",
                AppleAppAttestEnvironment.DEVELOPMENT, clock = fixedClock
            )
        }

        "validation works for valid attestation object" {
            val attestationSampleJson = javaClass.readTextResource("/iOS14-attestation-sample.json")
            val attestationSample: AttestationSample = jsonObjectMapper.readValue(attestationSampleJson)

            AttestationValidator(
                appTeamIdentifier = attestationSample.teamIdentifier,
                appBundleIdentifier = attestationSample.bundleIdentifier,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT,
                clock = Clock.fixed(attestationSample.timestamp.plusSeconds(5), ZoneOffset.UTC)
            ).validate(
                attestationObject = attestationSample.attestation,
                keyIdBase64 = attestationSample.keyId.toBase64(),
                serverChallenge = attestationSample.clientData
            )
        }
    }
}
