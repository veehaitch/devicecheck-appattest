package ch.veehait.devicecheck.appattest.attestation

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
class AttestationSample(
    id: UUID,
    type: SampleType,
    bundleIdentifier: String,
    environment: AppleAppAttestEnvironment,
    @JsonProperty("clientDataBase64")
    val clientData: ByteArray,
    @JsonProperty("clientDataHashSha256Base64")
    val clientDataHashSha256: ByteArray,
    @JsonProperty("keyIdBase64")
    keyId: ByteArray,
    teamIdentifier: String,
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    timestamp: Instant,
    @JsonProperty("attestationBase64")
    val attestation: ByteArray,
    @JsonDeserialize(using = ECPublicKeyDeserializer::class)
    publicKey: ECPublicKey,
    val iOSVersion: String,
) : Sample(id, type, bundleIdentifier, environment, keyId, teamIdentifier, timestamp, publicKey) {
    companion object {
        val all: List<AttestationSample>
            get() = Sample.all.filterIsInstance(AttestationSample::class.java)
    }
}
