package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.Extensions.get
import ch.veehait.devicecheck.appattest.Utils
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DLSet
import org.bouncycastle.cms.CMSSignedData
import java.security.cert.X509Certificate
import java.time.Instant

data class Receipt(
    val payload: ReceiptPayload,
    val p7: ByteArray,
) {
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

enum class ReceiptType {
    ATTEST, RECEIPT
}

data class ReceiptPayload(
    val appId: String,
    val attestationCertificate: X509Certificate,
    val clientHash: ByteArray,
    val token: String,
    val receiptType: ReceiptType,
    val environment: String?,
    val creationTime: Instant,
    val riskMetric: Int?,
    val notBefore: Instant?,
    val expirationTime: Instant,
) {
    companion object {
        /**
         *
         * According to Apple, the App Attest receipt is similar to an App Store receipt. The ASN.1 encoded
         * [signedData] follows the following specification:
         *
         *   ReceiptAttribute ::= SEQUENCE {
         *       type    INTEGER,
         *       version INTEGER,
         *       value   OCTET STRING
         *   }
         *   Payload ::= SET OF ReceiptAttribute
         *
         */
        fun parse(signedData: CMSSignedData): ReceiptPayload {
            val set = ASN1InputStream(signedData.signedContent.content as ByteArray).readObject() as DLSet
            val objs = set.objects.toList().map { it as ASN1Sequence }.associate {
                it.get<ASN1Integer>(0).intValueExact() to it.get<DEROctetString>(2).octets
            }

            val objAt: (Int) -> ByteArray? = { type -> objs[type] }
            val stringAt: (Int) -> String? = { type -> objAt(type)?.let(::String) }
            val instantAt: (Int) -> Instant? = { type ->
                stringAt(type)?.takeIf { value -> value.isNotBlank() }?.let(Instant::parse)
            }

            @Suppress("MagicNumber")
            return ReceiptPayload(
                // 2: App ID
                appId = stringAt(2)!!,
                // 3: Attested Public Key
                attestationCertificate = Utils.readDerX509Certificate(objAt(3)!!),
                // 4: Client Hash
                clientHash = objAt(4)!!,
                // 5: Token
                token = stringAt(5)!!,
                // 6: Receipt Type
                receiptType = ReceiptType.valueOf(stringAt(6)!!),
                // 7: XXX: Not mentioned in Apples docs
                environment = stringAt(7),
                // 12: Creation Time
                creationTime = instantAt(12)!!,
                // 17: Risk Metric; null for receipt type "ATTEST"
                riskMetric = stringAt(17)?.takeIf { it.isNotBlank() }?.let { Integer.parseInt(it) },
                // 19: Not Before; null for receipt type "ATTEST"
                notBefore = instantAt(19),
                // 21: Expiration Time
                expirationTime = instantAt(21)!!,
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ReceiptPayload

        if (appId != other.appId) return false
        if (attestationCertificate != other.attestationCertificate) return false
        if (!clientHash.contentEquals(other.clientHash)) return false
        if (token != other.token) return false
        if (receiptType != other.receiptType) return false
        if (environment != other.environment) return false
        if (creationTime != other.creationTime) return false
        if (riskMetric != other.riskMetric) return false
        if (notBefore != other.notBefore) return false
        if (expirationTime != other.expirationTime) return false

        return true
    }

    override fun hashCode(): Int {
        var result = appId.hashCode()
        result = 31 * result + attestationCertificate.hashCode()
        result = 31 * result + clientHash.contentHashCode()
        result = 31 * result + token.hashCode()
        result = 31 * result + receiptType.hashCode()
        result = 31 * result + (environment?.hashCode() ?: 0)
        result = 31 * result + creationTime.hashCode()
        result = 31 * result + (riskMetric ?: 0)
        result = 31 * result + notBefore.hashCode()
        result = 31 * result + expirationTime.hashCode()
        return result
    }
}
