package ch.veehait.devicecheck.appattest

import ch.veehait.devicecheck.appattest.TestExtensions.readTextResource
import ch.veehait.devicecheck.appattest.TestUtils.loadValidAttestationSample
import ch.veehait.devicecheck.appattest.attestation.AppleAppAttestValidationResponse
import ch.veehait.devicecheck.appattest.attestation.AttestationObject
import ch.veehait.devicecheck.appattest.attestation.AttestationSample
import ch.veehait.devicecheck.appattest.attestation.AttestationValidator
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.common.AttestedCredentialData
import ch.veehait.devicecheck.appattest.common.AuthenticatorData
import ch.veehait.devicecheck.appattest.common.AuthenticatorDataFlag
import ch.veehait.devicecheck.appattest.receipt.Receipt
import ch.veehait.devicecheck.appattest.util.Extensions.toBase64
import ch.veehait.devicecheck.appattest.util.Utils
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.readValue
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.StringWriter
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.ZoneOffset
import kotlin.experimental.or

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
}

object TestUtils {
    val jsonObjectMapper: ObjectMapper = ObjectMapper(JsonFactory())
        .registerModule(JavaTimeModule())
        .registerKotlinModule()

    val cborObjectMapper: ObjectMapper = ObjectMapper(CBORFactory()).registerKotlinModule()

    fun loadValidAttestationSample(): Triple<AttestationSample, App, Clock> {
        val attestationSampleJson = javaClass.readTextResource("/iOS14-attestation-sample.json")
        val attestationSample: AttestationSample = jsonObjectMapper.readValue(attestationSampleJson)
        val app = App(attestationSample.teamIdentifier, attestationSample.bundleIdentifier)
        val clock = Clock.fixed(attestationSample.timestamp.plusSeconds(5), ZoneOffset.UTC)
        return Triple(attestationSample, app, clock)
    }

    fun loadValidatedAttestationResponse(): Triple<AppleAppAttestValidationResponse, AppleAppAttest, Clock> {
        val (attestationSample, app, clock) = loadValidAttestationSample()
        val appleAppAttest = AppleAppAttest(
            app = app,
            appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT
        )
        val attestationValidator = appleAppAttest.createAttestationValidator(
            clock = clock,
            receiptValidator = appleAppAttest.createReceiptValidator(
                clock = clock
            )
        )
        val attestationResponse = attestationValidator.validate(
            attestationObject = attestationSample.attestation,
            keyIdBase64 = attestationSample.keyId.toBase64(),
            serverChallenge = attestationSample.clientData
        )

        return Triple(attestationResponse, appleAppAttest, clock)
    }
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

    val sampleChain: AttestationCertificateChain
        get() {
            val cborObjectMapper = ObjectMapper(CBORFactory()).registerKotlinModule()

            val (attestationSample, _, _) = loadValidAttestationSample()
            val attestationObject: AttestationObject = cborObjectMapper.readValue(attestationSample.attestation)

            return AttestationCertificateChain(
                rootCa = AttestationValidator.APPLE_APP_ATTEST_ROOT_CA_BUILTIN_TRUST_ANCHOR.trustedCert,
                intermediateCa = Utils.readDerX509Certificate(attestationObject.attStmt.x5c.last()),
                credCert = Utils.readDerX509Certificate(attestationObject.attStmt.x5c.first()),
            )
        }

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

    fun createCertificate(
        certTemplate: X509Certificate,
        keyPair: KeyPair = generateEcKeyPair(certTemplate),
        mutator: BuilderMutator = { Unit },
        issuerKeyPair: KeyPair = generateEcKeyPair(certTemplate),
        issuer: X500Name? = null,
    ): Pair<X509Certificate, KeyPair> {
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

        return Pair(cert, keyPair)
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

    fun createCustomReceipt(
        receipt: Receipt
    ): ByteArray {

        return ByteArray(0)
    }
}

typealias BuilderMutator = (X509v3CertificateBuilder) -> Unit
