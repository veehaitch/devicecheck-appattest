package ch.veehait.devicecheck.appattest.assertion

import com.fasterxml.jackson.annotation.JsonFormat
import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

@Suppress("ArrayInDataClass")
data class AssertionSample(
    @JsonProperty("assertionBase64")
    val assertion: ByteArray,
    val bundleIdentifier: String,
    @JsonProperty("challengeBase64")
    val challenge: ByteArray,
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
)
