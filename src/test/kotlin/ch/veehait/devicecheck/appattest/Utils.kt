package ch.veehait.devicecheck.appattest

import ch.veehait.devicecheck.appattest.TestExtensions.encode
import ch.veehait.devicecheck.appattest.attestation.AttestationValidator
import ch.veehait.devicecheck.appattest.common.AttestedCredentialData
import ch.veehait.devicecheck.appattest.common.AuthenticatorData
import ch.veehait.devicecheck.appattest.common.AuthenticatorDataFlag
import ch.veehait.devicecheck.appattest.receipt.Receipt
import ch.veehait.devicecheck.appattest.receipt.ReceiptValidator
import ch.veehait.devicecheck.appattest.util.Extensions.Pkcs7.readAsSignedData
import ch.veehait.devicecheck.appattest.util.Extensions.Pkcs7.readCertificateChain
import ch.veehait.devicecheck.appattest.util.Extensions.toBase64
import ch.veehait.devicecheck.appattest.util.Utils
import com.fasterxml.jackson.databind.MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLSet
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.cms.Time
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.StringWriter
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Date
import kotlin.experimental.or
import kotlin.reflect.full.memberProperties

object TestExtensions {
    fun <T> Class<T>.readTextResource(name: String, commentLinePrefix: String = "#"): String =
        getResource(name).readText().split("\n")
            .filterNot { it.startsWith(commentLinePrefix) || it.isBlank() }.joinToString("\n")

    fun List<AuthenticatorDataFlag>.encode(): ByteArray {
        return byteArrayOf(this.fold(0.toByte()) { acc, flag -> acc or flag.bitmask })
    }

    fun AttestedCredentialData.encode(): ByteArray {
        val aaguidBytes = ByteBuffer.allocate(16)
            .putLong(aaguid.mostSignificantBits)
            .putLong(aaguid.leastSignificantBits)
            .array()

        val credentialIdLengthBytes = ByteBuffer.allocate(4)
            .putInt(credentialId.size)
            .array().takeLast(2).toByteArray()

        val cborObjectMapper = ObjectMapper(CBORFactory())
        val credentialPublicKeyBytes = cborObjectMapper.writeValueAsBytes(credentialPublicKey)

        return aaguidBytes + credentialIdLengthBytes + credentialId + credentialPublicKeyBytes
    }

    fun AuthenticatorData.encode(): ByteArray {
        val cborObjectMapper = ObjectMapper(CBORFactory())

        return rpIdHash +
            flags.encode() +
            ByteBuffer.allocate(8).putLong(signCount).array().takeLast(4).toByteArray() +
            (attestedCredentialData?.encode() ?: ByteArray(0)) +
            (extensions?.let(cborObjectMapper::writeValueAsBytes) ?: ByteArray(0))
    }

    fun <T> Receipt.ReceiptAttribute<T>?.encodeValue(value: T? = this?.value): ByteArray? = when (this) {
        is Receipt.ReceiptAttribute.String -> (value as String).toByteArray()
        is Receipt.ReceiptAttribute.X509Certificate -> (value as X509Certificate).encoded
        is Receipt.ReceiptAttribute.ByteArray -> value as ByteArray
        is Receipt.ReceiptAttribute.Type -> (value as Receipt.Type).name.toByteArray()
        is Receipt.ReceiptAttribute.Instant -> (value as Instant).toString().toByteArray()
        is Receipt.ReceiptAttribute.Int -> (value as Int).toString().toByteArray()
        null -> ByteArray(0)
    }

    fun <T> Receipt.ReceiptAttribute<T>.encode(): ASN1Sequence = DLSequence(
        arrayOf(
            ASN1Integer(type.field.toLong()),
            ASN1Integer(version.toLong()),
            DEROctetString(encodeValue()),
        )
    )

    fun Receipt.Payload.encode(): ByteArray = Receipt.Payload::class.memberProperties
        .map { it.get(this) }
        .filterNotNull()
        .map { it as Receipt.ReceiptAttribute<*> }
        .sortedBy { it.type.field }
        .map { it.encode() }
        .toTypedArray()
        .let(::DLSet)
        .encoded

    fun Receipt.ReceiptAttribute.String?.copy(newValue: String): Receipt.ReceiptAttribute.String? =
        this?.encodeValue(newValue)?.let { Receipt.ReceiptAttribute.String(sequence.copy(value = it)) }

    fun Receipt.ReceiptAttribute.X509Certificate?.copy(newValue: X509Certificate):
        Receipt.ReceiptAttribute.X509Certificate? = this?.encodeValue(newValue)?.let {
        Receipt.ReceiptAttribute.X509Certificate(sequence.copy(value = it))
    }

    fun Receipt.ReceiptAttribute.ByteArray?.copy(newValue: ByteArray): Receipt.ReceiptAttribute.ByteArray? =
        this?.encodeValue(newValue)?.let { Receipt.ReceiptAttribute.ByteArray(sequence.copy(value = it)) }

    fun Receipt.ReceiptAttribute.Type?.copy(newValue: Receipt.Type): Receipt.ReceiptAttribute.Type? =
        this?.encodeValue(newValue)?.let { Receipt.ReceiptAttribute.Type(sequence.copy(value = it)) }

    fun Receipt.ReceiptAttribute.Instant?.copy(newValue: Instant): Receipt.ReceiptAttribute.Instant? =
        this?.encodeValue(newValue)?.let { Receipt.ReceiptAttribute.Instant(sequence.copy(value = it)) }

    fun Receipt.ReceiptAttribute.Int?.copy(newValue: Int): Receipt.ReceiptAttribute.Int? =
        this?.encodeValue(newValue)?.let { Receipt.ReceiptAttribute.Int(sequence.copy(value = it)) }

    fun ByteArray.md5(): ByteArray = MessageDigest.getInstance("MD5").digest(this)

    fun Instant.fixedUtcClock() = Clock.fixed(this, ZoneOffset.UTC)
}

object TestUtils {
    val cborObjectMapper = CBORMapper
        .builder()
        .enable(ACCEPT_CASE_INSENSITIVE_ENUMS)
        .build()
        .registerKotlinModule()
}

object CertUtils {
    init {
        Security.addProvider(BouncyCastleProvider())
    }

    data class AttestationCertificateChain(
        val rootCa: X509Certificate,
        val intermediateCa: X509Certificate,
        val credCert: X509Certificate,
    )

    private fun PublicKey.getEcCurveName(): String {
        val spki = SubjectPublicKeyInfo.getInstance(this.encoded)
        check(spki.algorithm.algorithm == X9ObjectIdentifiers.id_ecPublicKey) {
            "Requires an EC public key"
        }
        val oid = (spki.algorithm.parameters as ASN1ObjectIdentifier)
        return ECUtil.getCurveName(oid)
    }

    private fun generateEcKeyPair(template: X509Certificate): KeyPair {
        val curveName = template.publicKey.getEcCurveName()
        val algorithm = template.publicKey.algorithm

        return KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME).apply {
            initialize(ECGenParameterSpec(curveName))
        }.generateKeyPair()
    }

    fun generateP256KeyPair(): KeyPair = KeyPairGenerator
        .getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
        .apply {
            ECGenParameterSpec("prime256v1").let(this::initialize)
        }.generateKeyPair()

    fun PrivateKey.toPEM(): String = listOf(
        "-----BEGIN PRIVATE KEY-----",
        encoded.toBase64(),
        "-----END PRIVATE KEY-----"
    ).joinToString("\n")

    /**
     * Converts a [X509Certificate] instance into a Base-64 encoded string (PEM format).
     *
     * @param x509Cert A X509 Certificate instance
     * @return PEM formatted String
     * @throws CertificateEncodingException
     */
    fun X509Certificate.toPEM(): String? {
        val sw = StringWriter()
        JcaPEMWriter(sw).use { pw -> pw.writeObject(this) }
        return sw.toString()
    }

    data class CertificateWithKeyPair(
        val certificate: X509Certificate,
        val keyPair: KeyPair,
    )

    fun createCertificate(
        certTemplate: X509Certificate,
        keyPair: KeyPair = generateEcKeyPair(certTemplate),
        mutator: BuilderMutator = { Unit },
        issuerKeyPair: KeyPair = generateEcKeyPair(certTemplate),
        issuer: X500Name? = null,
    ): CertificateWithKeyPair {
        val holder = X509CertificateHolder(certTemplate.encoded)

        val builder = X509v3CertificateBuilder(
            issuer ?: holder.issuer,
            holder.serialNumber,
            holder.notBefore,
            holder.notAfter,
            holder.subject,
            SubjectPublicKeyInfo.getInstance(keyPair.public.encoded),
        )

        holder.extensionOIDs.map {
            it as ASN1ObjectIdentifier
            holder.extensions.getExtension(it)
        }.forEach {
            builder.addExtension(it)
        }

        mutator(builder)

        val sigGen = JcaContentSignerBuilder(certTemplate.sigAlgName).build(issuerKeyPair.private)

        val cert = JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(builder.build(sigGen))

        return CertificateWithKeyPair(cert, keyPair)
    }

    private fun buildAttestationCertificateChain(x5c: List<ByteArray>): AttestationCertificateChain {
        return AttestationCertificateChain(
            rootCa = AttestationValidator.APPLE_APP_ATTEST_ROOT_CA_BUILTIN_TRUST_ANCHOR.trustedCert,
            intermediateCa = Utils.readDerX509Certificate(x5c.last()),
            credCert = Utils.readDerX509Certificate(x5c.first()),
        )
    }

    fun createCustomAttestationCertificate(
        x5c: List<ByteArray>,
        credCertKeyPair: KeyPair,
        mutatorRootCa: BuilderMutator = { Unit },
        mutatorIntermediateCa: BuilderMutator = { Unit },
        mutatorCredCert: BuilderMutator = { Unit },
    ): AttestationCertificateChain {
        val x5cChain = buildAttestationCertificateChain(x5c)

        val (rootCa, rootCaKeyPair) = createCertificate(
            certTemplate = x5cChain.rootCa,
            mutator = mutatorRootCa
        )
        val (intermediateCa, intermediateCaKeyPair) = createCertificate(
            certTemplate = x5cChain.intermediateCa,
            mutator = mutatorIntermediateCa,
            issuerKeyPair = rootCaKeyPair,
            issuer = X509CertificateHolder(rootCa.encoded).subject,
        )
        val (credCert, _) = createCertificate(
            certTemplate = x5cChain.credCert,
            keyPair = credCertKeyPair,
            mutator = mutatorCredCert,
            issuerKeyPair = intermediateCaKeyPair,
            issuer = X509CertificateHolder(intermediateCa.encoded).subject,
        )

        return AttestationCertificateChain(
            rootCa = rootCa,
            intermediateCa = intermediateCa,
            credCert = credCert,
        )
    }

    data class ResignedReceiptResponse(
        val receipt: Receipt,
        val trustAnchor: TrustAnchor,
        val leafCertificate: X509Certificate,
    )

    fun resignReceipt(
        receipt: Receipt,
        rootCaBundle: CertificateWithKeyPair = createCertificate(
            certTemplate = ReceiptValidator.APPLE_PUBLIC_ROOT_CA_G3_BUILTIN_TRUST_ANCHOR.trustedCert
        ),
        payloadMutator: (Receipt.Payload) -> Receipt.Payload = { it },
        generatorMutator: (CMSSignedDataGenerator) -> Unit = {},
    ): ResignedReceiptResponse {
        val certificateChain = receipt.p7.readAsSignedData().readCertificateChain().asReversed()

        val certChainBundle = certificateChain
            .runningFold(rootCaBundle) { issuerBundle, template ->
                createCertificate(
                    certTemplate = template,
                    issuerKeyPair = issuerBundle.keyPair,
                    issuer = X509CertificateHolder(issuerBundle.certificate.encoded).subject,
                )
            }.drop(1)

        val credCertBundle = certChainBundle.last()

        // Set the `signing-time` explicitly to the creation time. Otherwise, it will be set to the current time.
        val creationTime = Time(Date.from(receipt.payload.creationTime.value))
        val signedTime = Attribute(CMSAttributes.signingTime, DERSet(creationTime))
        val signedAttributes = ASN1EncodableVector().apply {
            add(signedTime)
        }
        val signedAttributesTable = AttributeTable(signedAttributes)
        val signedAttributeGenerator = DefaultSignedAttributeTableGenerator(signedAttributesTable)

        val generator = CMSSignedDataGenerator().apply {
            certChainBundle.asReversed().map { it.certificate }.forEach {
                addCertificate(X509CertificateHolder(it.encoded))
            }

            addSignerInfoGenerator(
                JcaSimpleSignerInfoGeneratorBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .setSignedAttributeGenerator(signedAttributeGenerator)
                    .build("SHA256withECDSA", credCertBundle.keyPair.private, credCertBundle.certificate)
            )
            generatorMutator(this)
        }

        val payloadNewCert = receipt.payload.copy(
            attestationCertificate = Receipt.ReceiptAttribute.X509Certificate(
                receipt.payload.attestationCertificate.sequence.copy(
                    value = credCertBundle.certificate.encoded
                )
            )
        ).let(payloadMutator)

        val p7s = payloadNewCert.encode()
            .let(::CMSProcessableByteArray)
            .let { generator.generate(it, true) }
            .encoded

        return ResignedReceiptResponse(
            receipt = receipt.copy(
                p7 = p7s
            ),
            trustAnchor = TrustAnchor(rootCaBundle.certificate, null),
            leafCertificate = credCertBundle.certificate,
        )
    }
}

typealias BuilderMutator = (X509v3CertificateBuilder) -> Unit
