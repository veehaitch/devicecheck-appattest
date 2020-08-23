package ch.veehait.devicecheck.appattest

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class AttestationValidatorTest : StringSpec() {
    init {
        val fixedClock = Clock.fixed(Instant.parse("2020-08-23T13:37:00.00Z"), ZoneOffset.UTC)

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
            AttestationValidator(
                "6MURL8TA57",
                "de.vincent-haupert.apple-appattest-poc",
                AppleAppAttestEnvironment.DEVELOPMENT,
                clock = fixedClock
            )
                .validate(
                    javaClass.readTextResource("/iOS14-attestation-response-base64.cbor"),
                    "/jINCLby0Zi1H/oA+IHr+GMMVMxfva0MWaDEcqWQGwc=",
                    "wurzelpfropf".toByteArray()
                )
        }
    }
}
