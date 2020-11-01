package ch.veehait.devicecheck.appattest

import ch.veehait.devicecheck.appattest.TestExtensions.readTextResource
import ch.veehait.devicecheck.appattest.attestation.AppleAppAttestValidationResponse
import ch.veehait.devicecheck.appattest.attestation.AttestationSample
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.util.Extensions.toBase64
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.readValue
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import java.time.Clock
import java.time.ZoneOffset

object TestExtensions {
    fun <T> Class<T>.readTextResource(name: String, commentLinePrefix: String = "#"): String =
        getResource(name).readText().split("\n")
            .filterNot { it.startsWith(commentLinePrefix) || it.isBlank() }.joinToString("\n")
}

object TestUtils {
    val jsonObjectMapper = ObjectMapper(JsonFactory())
        .registerModule(JavaTimeModule())
        .registerModule(KotlinModule())

    val cborObjectMapper = ObjectMapper(CBORFactory()).registerKotlinModule()

    fun loadValidAttestationSample(): Triple<AttestationSample, App, Clock> {
        val attestationSampleJson = javaClass.readTextResource("/iOS14-attestation-sample.json")
        val attestationSample: AttestationSample = jsonObjectMapper.readValue(attestationSampleJson)
        val app = App(attestationSample.teamIdentifier, attestationSample.bundleIdentifier)
        val clock = Clock.fixed(attestationSample.timestamp.plusSeconds(5), ZoneOffset.UTC)
        return Triple(attestationSample, app, clock)
    }

    fun loadValidatedAttestationResponse(): Triple<AppleAppAttestValidationResponse, AppleAppAttest, Clock> {
        val (attestationSample, app, clock) = loadValidAttestationSample()
        val appleAppAttest = AppleAppAttest(
            app = app,
            appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
        )
        val attestationValidator = appleAppAttest.createAttestationValidator(
            clock = clock,
            receiptValidator = appleAppAttest.createReceiptValidator(
                clock = clock
            )
        )
        val attestationResponse = attestationValidator.validate(
            attestationObject = attestationSample.attestation,
            keyIdBase64 = attestationSample.keyId.toBase64(),
            serverChallenge = attestationSample.clientData
        )

        return Triple(attestationResponse, appleAppAttest, clock)
    }
}
