package ch.veehait.devicecheck.appattest

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import java.lang.IllegalArgumentException
import java.net.URL

class AttestationValidatorTest : StringSpec() {

    private val appleAppAttestRootCA = downloadAppAttestCA()

    private fun downloadAppAttestCA(): String {
        return URL("https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem")
            .openStream().bufferedReader().readText()
    }

    init {
        "team identifier must consist of 10 characters" {
            shouldThrow<IllegalArgumentException> {
                AttestationValidator("a".repeat(9), "", appleAppAttestRootCA, AppleAppAttestEnvironment.DEVELOPMENT)
            }
            shouldThrow<IllegalArgumentException> {
                AttestationValidator("a".repeat(11), "", appleAppAttestRootCA, AppleAppAttestEnvironment.DEVELOPMENT)
            }
            AttestationValidator("a".repeat(10), "", appleAppAttestRootCA, AppleAppAttestEnvironment.DEVELOPMENT)
        }

        "validation works for valid attestation object" {
            AttestationValidator(
                "6MURL8TA57",
                "de.vincent-haupert.AppleAppAttestPoc",
                appleAppAttestRootCA,
                AppleAppAttestEnvironment.DEVELOPMENT)
                .validate(
                    javaClass.readTextResource("/iOS14-attestation-response-base64.cbor"),
                    "XGr5wqmUab/9M4b5vxa6KkPOigfeEWDaw7tuK02aJ6c=",
                    "wurzelpfropf".toByteArray()
                )
        }
    }
}