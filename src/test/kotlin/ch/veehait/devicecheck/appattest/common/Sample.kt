package ch.veehait.devicecheck.appattest.common

import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.TestExtensions.md5
import ch.veehait.devicecheck.appattest.assertion.AssertionSample
import ch.veehait.devicecheck.appattest.attestation.AttestationSample
import ch.veehait.devicecheck.appattest.receipt.ReceiptSample
import ch.veehait.devicecheck.appattest.util.Extensions.toBase64
import ch.veehait.devicecheck.appattest.util.Extensions.toUUID
import com.fasterxml.jackson.annotation.JsonFormat
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.MapperFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.readValues
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.fasterxml.jackson.module.kotlin.treeToValue
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.UUID

enum class SampleType {
    Attestation,
    Assertion,
    Receipt,
}

@Suppress("LongParameterList")
@JsonIgnoreProperties(ignoreUnknown = true)
open class Sample(
    val id: UUID,
    val type: SampleType,
    val bundleIdentifier: String,
    val environment: AppleAppAttestEnvironment,
    @JsonProperty("keyIdBase64")
    val keyId: ByteArray,
    val teamIdentifier: String,
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    val timestamp: Instant,
    @JsonDeserialize(using = ECPublicKeyDeserializer::class)
    val publicKey: ECPublicKey,
) {
    fun defaultAppleAppAttest() = AppleAppAttest(
        app = App(teamIdentifier, bundleIdentifier),
        appleAppAttestEnvironment = environment
    )

    companion object {
        private fun loadSample(name: String): List<Sample> {
            val yamlObjectMapper: ObjectMapper = ObjectMapper(YAMLFactory())
                .registerModule(JavaTimeModule())
                .registerKotlinModule()
                .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS)

            val url = this::class.java.getResource(name)
            val yamlParser = YAMLFactory().createParser(url)
            val objs: List<Sample> = yamlObjectMapper
                .readValues<ObjectNode>(yamlParser)
                .readAll()
                .map {
                    val obj = yamlObjectMapper.treeToValue<Sample>(it)
                    val clazz = when (obj!!.type) {
                        SampleType.Attestation -> AttestationSample::class.java
                        SampleType.Assertion -> AssertionSample::class.java
                        SampleType.Receipt -> ReceiptSample::class.java
                    }
                    yamlObjectMapper.treeToValue(it, clazz).apply {
                        @Suppress("TooGenericExceptionThrown")
                        val payload = when (this) {
                            is AttestationSample -> attestation
                            is AssertionSample -> assertion
                            is ReceiptSample -> receipt

                            else -> throw RuntimeException("Should never occur")
                        }
                        assert(payload.md5().toUUID() == this.id) {
                            "ID should be the MD5 digest of the sample's payload represented as UUID but was not"
                        }
                    }
                }

            assert(objs.map { it.keyId.toBase64() }.toSet().size == 1) {
                "A single YAML file should only contain samples for the same attestation"
            }

            return objs
        }

        val all: List<Sample>
            get() = listOf(
                "/ios-14.2.yaml",
                "/ios-14.3-beta-2.yaml",
                "/ios-14.3-beta-3.yaml",
                "/ios-14.3.yaml",
                "/ios-14.4-beta-1.yaml",
                "/ios-14.4-beta-2.yaml",
                "/ios-14.4.yaml",
            )
                .map(this::loadSample)
                .flatten()
    }
}

class ECPublicKeyDeserializer : JsonDeserializer<ECPublicKey>() {
    override fun deserialize(p: JsonParser?, ctxt: DeserializationContext?): ECPublicKey {
        val input = p!!.text.toByteArray().inputStream()
        val pemParser = PEMParser(input.reader())
        val keyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject())
        val factory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
        return factory.generatePublic(X509EncodedKeySpec(keyInfo.encoded)) as ECPublicKey
    }
}
