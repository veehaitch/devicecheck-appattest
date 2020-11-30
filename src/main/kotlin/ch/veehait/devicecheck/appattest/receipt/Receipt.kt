package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.util.Extensions.get
import ch.veehait.devicecheck.appattest.util.Utils
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DLSet
import org.bouncycastle.cms.CMSSignedData
import java.math.BigInteger

data class Receipt(
    val payload: Payload,
    val p7: ByteArray,
) {
    enum class Type {
        ATTEST, RECEIPT
    }

    /**
     * According to Apple, the App Attest receipt is similar to an App Store receipt. The ASN.1 encoded
     * signedData follows the following specification:
     *
     *   ReceiptAttribute ::= SEQUENCE {
     *       type    INTEGER,
     *       version INTEGER,
     *       value   OCTET STRING
     *   }
     *   Payload ::= SET OF ReceiptAttribute
     */
    data class AttributeSequence(
        val type: BigInteger,
        val version: BigInteger,
        val value: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as AttributeSequence

            if (type != other.type) return false
            if (version != other.version) return false
            if (!value.contentEquals(other.value)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = type.hashCode()
            result = 31 * result + version.hashCode()
            result = 31 * result + value.contentHashCode()
            return result
        }
    }

    @Suppress("MagicNumber")
    enum class AttributeType(val field: Int) {
        APP_ID(2),
        ATTESTED_PUBLIC_KEY(3),
        CLIENT_HASH(4),
        TOKEN(5),
        RECEIPT_TYPE(6),

        /** This field is not mentioned in Apple's documentation */
        ENVIRONMENT(7),
        CREATION_TIME(12),
        RISK_METRIC(17),
        NOT_BEFORE(19),
        EXPIRATION_TIME(21);

        companion object {
            fun fromFieldValue(value: Int) = values().first { it.field == value }
        }
    }

    sealed class ReceiptAttribute<T>(internal val sequence: AttributeSequence) {
        val type: AttributeType = AttributeType.fromFieldValue(sequence.type.intValueExact())
        val version: kotlin.Int = sequence.version.intValueExact()
        protected val rawValue = sequence.value

        abstract val value: T

        override fun toString(): kotlin.String = value.toString()

        class String(sequence: AttributeSequence) : ReceiptAttribute<kotlin.String>(sequence) {
            override val value: kotlin.String = String(rawValue)
        }

        class X509Certificate(
            sequence: AttributeSequence
        ) : ReceiptAttribute<java.security.cert.X509Certificate>(sequence) {
            override val value: java.security.cert.X509Certificate = Utils.readDerX509Certificate(rawValue)
        }

        class ByteArray(sequence: AttributeSequence) : ReceiptAttribute<kotlin.ByteArray>(sequence) {
            override val value: kotlin.ByteArray = rawValue
        }

        class Type(sequence: AttributeSequence) : ReceiptAttribute<Receipt.Type>(sequence) {
            override val value: Receipt.Type = Receipt.Type.valueOf(String(sequence).value)
        }

        class Instant(sequence: AttributeSequence) : ReceiptAttribute<java.time.Instant>(sequence) {
            override val value: java.time.Instant = java.time.Instant.parse(String(sequence).value)
        }

        class Int(sequence: AttributeSequence) : ReceiptAttribute<kotlin.Int>(sequence) {
            override val value: kotlin.Int = java.lang.Integer.parseInt(String(sequence).value)
        }
    }

    data class Payload(
        val appId: ReceiptAttribute.String,
        val attestationCertificate: ReceiptAttribute.X509Certificate,
        val clientHash: ReceiptAttribute.ByteArray,
        val token: ReceiptAttribute.String,
        val type: ReceiptAttribute.Type,
        val environment: ReceiptAttribute.String?,
        val creationTime: ReceiptAttribute.Instant,
        val riskMetric: ReceiptAttribute.Int?,
        val notBefore: ReceiptAttribute.Instant?,
        val expirationTime: ReceiptAttribute.Instant,
    ) {
        companion object {
            @JvmStatic
            fun parse(signedData: CMSSignedData): Payload {
                val set = ASN1InputStream(signedData.signedContent.content as ByteArray).readObject() as DLSet
                val objs = set.objects
                    .toList()
                    .map { it as ASN1Sequence }
                    .map {
                        AttributeSequence(
                            type = it.get<ASN1Integer>(0).positiveValue,
                            version = it.get<ASN1Integer>(1).positiveValue,
                            value = it.get<DEROctetString>(2).octets
                        )
                    }.associateBy { it.type.toInt() }

                fun objAt(type: AttributeType): AttributeSequence = objs[type.field]
                    ?: error("Receipt must contain field ${type.name}")

                fun objAtOptional(type: AttributeType, required: Boolean = false): AttributeSequence? {
                    return when (required) {
                        true -> objAt(type)
                        false -> objs[type.field]
                    }
                }

                val type = ReceiptAttribute.Type(objAt(AttributeType.RECEIPT_TYPE))

                return Payload(
                    appId = ReceiptAttribute.String(objAt(AttributeType.APP_ID)),
                    attestationCertificate = ReceiptAttribute.X509Certificate(
                        objAt(AttributeType.ATTESTED_PUBLIC_KEY)
                    ),
                    clientHash = ReceiptAttribute.ByteArray(objAt(AttributeType.CLIENT_HASH)),
                    token = ReceiptAttribute.String(objAt(AttributeType.TOKEN)),
                    type = type,
                    environment = objAtOptional(AttributeType.ENVIRONMENT)?.let { ReceiptAttribute.String(it) },
                    creationTime = ReceiptAttribute.Instant(objAt(AttributeType.CREATION_TIME)),
                    riskMetric = objAtOptional(
                        AttributeType.RISK_METRIC,
                        required = type.value == Type.RECEIPT
                    )?.let { ReceiptAttribute.Int(it) },
                    notBefore = objAtOptional(
                        AttributeType.NOT_BEFORE,
                        required = type.value == Type.RECEIPT
                    )?.let { ReceiptAttribute.Instant(it) },
                    expirationTime = ReceiptAttribute.Instant(objAt(AttributeType.EXPIRATION_TIME)),
                )
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Receipt

        if (payload != other.payload) return false
        if (!p7.contentEquals(other.p7)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = payload.hashCode()
        result = 31 * result + p7.contentHashCode()
        return result
    }
}
