package ch.veehait.devicecheck.appattest.assertion

import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.common.ECPublicKeyDeserializer
import ch.veehait.devicecheck.appattest.common.Sample
import ch.veehait.devicecheck.appattest.common.SampleType
import com.fasterxml.jackson.annotation.JsonFormat
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.util.UUID

@Suppress("LongParameterList")
class AssertionSample(
    id: UUID,
    type: SampleType,
    @JsonProperty("keyIdBase64")
    keyId: ByteArray,
    teamIdentifier: String,
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    timestamp: Instant,
    bundleIdentifier: String,
    environment: AppleAppAttestEnvironment,
    @JsonDeserialize(using = ECPublicKeyDeserializer::class)
    publicKey: ECPublicKey,
    @JsonProperty("assertionBase64")
    val assertion: ByteArray,
    @JsonProperty("challengeBase64")
    val challenge: ByteArray,
    @JsonProperty("clientDataBase64")
    val clientData: ByteArray,
    @JsonProperty("clientDataHashSha256Base64")
    val clientDataHashSha256: ByteArray,
    val counter: Long
) : Sample(id, type, bundleIdentifier, environment, keyId, teamIdentifier, timestamp, publicKey) {
    companion object {
        val all: List<AssertionSample>
            get() = Sample.all.filterIsInstance(AssertionSample::class.java)
    }
}
