package ch.veehait.devicecheck.appattest

import ch.veehait.devicecheck.appattest.TestExtensions.readTextResource
import ch.veehait.devicecheck.appattest.attestation.AttestationSample
import ch.veehait.devicecheck.appattest.common.App
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
}
