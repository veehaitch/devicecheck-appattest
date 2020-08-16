package ch.veehait.devicecheck.appattest

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec

class AttestationValidatorTest : StringSpec() {
    init {
        "team identifier must consist of 10 characters" {
            shouldThrow<IllegalArgumentException> {
                AttestationValidator("a".repeat(9), "", AppleAppAttestEnvironment.DEVELOPMENT)
            }
            shouldThrow<IllegalArgumentException> {
                AttestationValidator("a".repeat(11), "", AppleAppAttestEnvironment.DEVELOPMENT)
            }
            AttestationValidator("a".repeat(10), "", AppleAppAttestEnvironment.DEVELOPMENT)
        }

        "validation works for valid attestation object" {
            AttestationValidator(
                "6MURL8TA57",
                "de.vincent-haupert.AppleAppAttestPoc",
                AppleAppAttestEnvironment.DEVELOPMENT)
                .validate(
                    javaClass.readTextResource("/iOS14-attestation-response-base64.cbor"),
                    "XGr5wqmUab/9M4b5vxa6KkPOigfeEWDaw7tuK02aJ6c=",
                    "wurzelpfropf".toByteArray()
                )
        }
    }
}