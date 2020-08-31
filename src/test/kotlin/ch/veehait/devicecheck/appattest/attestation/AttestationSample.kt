package ch.veehait.devicecheck.appattest.attestation

import com.fasterxml.jackson.annotation.JsonFormat
import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

@Suppress("ArrayInDataClass")
data class AttestationSample(
    val bundleIdentifier: String,
    @JsonProperty("clientDataBase64")
    val clientData: ByteArray,
    @JsonProperty("clientDataHashSha256Base64")
    val clientDataHashSha256: ByteArray,
    @JsonProperty("keyIdBase64")
    val keyId: ByteArray,
    val teamIdentifier: String,
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    val timestamp: Instant,
    val type: String,
    @JsonProperty("attestationBase64")
    val attestation: ByteArray,
)
