package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.common.ECPublicKeyDeserializer
import ch.veehait.devicecheck.appattest.common.Sample
import ch.veehait.devicecheck.appattest.common.SampleType
import com.fasterxml.jackson.annotation.JsonFormat
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import java.security.cert.TrustAnchor
import java.security.interfaces.ECPublicKey
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

class ReceiptSample(
    id: UUID,
    type: SampleType,
    bundleIdentifier: String,
    environment: AppleAppAttestEnvironment,
    @JsonProperty("keyIdBase64")
    keyId: ByteArray,
    teamIdentifier: String,
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    timestamp: Instant,
    @JsonDeserialize(using = ECPublicKeyDeserializer::class)
    publicKey: ECPublicKey,
    @JsonProperty("receiptBase64")
    val receipt: ByteArray,
    val properties: Properties,
) : Sample(id, type, bundleIdentifier, environment, keyId, teamIdentifier, timestamp, publicKey) {
    @Suppress("ArrayInDataClass")
    data class Properties(
        @JsonProperty("clientHashBase64")
        val clientHash: ByteArray,
        @JsonFormat(shape = JsonFormat.Shape.STRING)
        val creationTime: Instant,
        val environment: String,
        @JsonFormat(shape = JsonFormat.Shape.STRING)
        val expirationTime: Instant,
        @JsonFormat(shape = JsonFormat.Shape.STRING)
        val notBefore: Instant?,
        val riskMetric: Int?,
        val token: String,
        val type: Receipt.Type,
    )

    companion object {
        val all: List<ReceiptSample>
            get() = Sample.all.filterIsInstance(ReceiptSample::class.java)
    }
}

class ReceiptSampleBundle(
    val sample: ReceiptSample,
    clock: Clock = Clock.fixed(sample.timestamp, ZoneOffset.UTC),
    trustAnchor: TrustAnchor = ReceiptValidator.APPLE_PUBLIC_ROOT_CA_G3_BUILTIN_TRUST_ANCHOR,
) {
    val appleAppAttest = AppleAppAttest(
        app = App(teamIdentifier = sample.teamIdentifier, bundleIdentifier = sample.bundleIdentifier),
        appleAppAttestEnvironment = sample.environment,
    )
    val validator = appleAppAttest.createReceiptValidator(
        trustAnchor = trustAnchor,
        clock = clock,
    )
}
