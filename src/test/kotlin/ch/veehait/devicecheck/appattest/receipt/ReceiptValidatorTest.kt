package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.App
import ch.veehait.devicecheck.appattest.Extensions.fromBase64
import ch.veehait.devicecheck.appattest.Extensions.toBase64
import ch.veehait.devicecheck.appattest.TestExtensions.readTextResource
import ch.veehait.devicecheck.appattest.attestation.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.attestation.AttestationSample
import ch.veehait.devicecheck.appattest.attestation.AttestationValidator
import ch.veehait.devicecheck.appattest.attestation.AttestationValidatorImpl
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.readValue
import io.kotest.core.spec.style.StringSpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class ReceiptValidatorTest : StringSpec() {
    private val jsonObjectMapper = ObjectMapper(JsonFactory())
        .registerModule(JavaTimeModule())
        .registerModule(KotlinModule())

    init {
        "validation succeeds for valid receipt" {
            // Test setup

            val attestationSampleJson = javaClass.readTextResource("/iOS14-attestation-sample.json")
            val attestationSample: AttestationSample = jsonObjectMapper.readValue(attestationSampleJson)

            val app = App(attestationSample.teamIdentifier, attestationSample.bundleIdentifier)
            val attestationSampleCreationTimeClock = Clock.fixed(
                attestationSample.timestamp.plusSeconds(5),
                ZoneOffset.UTC
            )
            val attestationValidator: AttestationValidator = AttestationValidatorImpl(
                app = app,
                appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT,
                clock = attestationSampleCreationTimeClock
            )
            val attestationResponse = attestationValidator.validate(
                attestationObject = attestationSample.attestation,
                keyIdBase64 = attestationSample.keyId.toBase64(),
                serverChallenge = attestationSample.clientData
            )

            // Actual test
            val receipt = javaClass
                .readTextResource("/iOS14-attestation-receipt-response-base64.der")
                .fromBase64()
            val assertionSampleCreationTimeClock = Clock.fixed(
                Instant.parse("2020-08-31T12:22:14.181Z").plusSeconds(5),
                ZoneOffset.UTC
            )

            val receiptValidator: ReceiptValidator = ReceiptValidatorImpl(
                app = app,
                clock = assertionSampleCreationTimeClock
            )
            receiptValidator.validateReceipt(
                receiptP7 = receipt,
                publicKey = attestationResponse.publicKey
            )
        }
    }
}
