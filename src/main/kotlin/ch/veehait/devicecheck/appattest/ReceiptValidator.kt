package ch.veehait.devicecheck.appattest

import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DLSet
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.GeneralSecurityException
import java.security.PublicKey
import java.security.Security
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Date

class ReceiptValidator(
    appleTeamIdentifier: String,
    appCfBundleIdentifier: String,
    applePublicRootCaPem: String = APPLE_PUBLIC_ROOT_CA_G3_BUILTIN,
    private val maxAge: Duration = APPLE_RECOMMENDED_MAX_AGE,
    private val clock: Clock = Clock.systemUTC()
) {
    companion object {
        val APPLE_PUBLIC_ROOT_CA_G3_BUILTIN =
            """
            -----BEGIN CERTIFICATE-----
            MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9v
            dCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UE
            CgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2
            WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmlj
            YXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqG
            SM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxE
            tX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNC
            MEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P
            AQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3m
            eoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkL
            F1vLUagM6BgD56KyKA==
            -----END CERTIFICATE-----
            """.trimIndent()

        val APPLE_RECOMMENDED_MAX_AGE: Duration = Duration.ofMinutes(5)
    }

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    private val appId = "$appleTeamIdentifier.$appCfBundleIdentifier"
    private val applePublicRootCa = readPemX590Certificate(applePublicRootCaPem)

    fun validate(receipt: ByteArray, publicKey: PublicKey): ReceiptPayload = runBlocking {
        validateAsync(receipt, publicKey)
    }

    suspend fun validateAsync(receipt: ByteArray, publicKey: PublicKey): ReceiptPayload = coroutineScope {
        val signedData = readSignedData(receipt)
        val certs = readCertificateChain(signedData)

        // XXX: Omitting signature check due to an Apple bug
        // 1. Verify the signature.
        // launch { verifySignature(signedData, certs.first()) }

        // 2. Evaluate the trustworthiness of the signing certificate up to the
        //    Apple public root certificate for App Attest.
        launch { verifyCertificateChain(certs) }

        verifyPayload(signedData, publicKey)
    }

    private fun readSignedData(data: ByteArray): CMSSignedData = ASN1InputStream(data).use {
        it.readObject().let(ContentInfo::getInstance).let(::CMSSignedData)
    }

    private fun readCertificateChain(signedData: CMSSignedData): List<X509Certificate> =
        signedData.certificates.getMatches(null).map {
            JcaX509CertificateConverter().getCertificate(it)
        }

    private fun verifyCertificateChain(certs: List<X509Certificate>) {
        try {
            verifyCertificateChain(certs, applePublicRootCa, date = Date.from(clock.instant()))
        } catch (ex: GeneralSecurityException) {
            throw ReceiptException.InvalidCertificateChain(
                "The assertion object does not contain a valid certificate chain",
                ex
            )
        }
    }

    private fun verifySignature(signedData: CMSSignedData, receiptCert: X509Certificate) {
        val signerInformation = signedData.signerInfos.signers.takeIf { it.size == 1 }?.first()
            ?: throw ReceiptException.InvalidSignature("The receipt contains more than one signature")

        val signerInformationVerifier = JcaSimpleSignerInfoVerifierBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(receiptCert)
        val signatureValid = signerInformation.verify(signerInformationVerifier)
        if (!signatureValid) {
            throw ReceiptException.InvalidSignature("The receipt signature is invalid")
        }
    }

    private fun parseProperties(signedData: CMSSignedData): ReceiptPayload {
        val set = ASN1InputStream(signedData.signedContent.content as ByteArray).readObject() as DLSet
        val objs = set.objects.toList().map { it as ASN1Sequence }.associate {
            Pair(
                Integer.parseInt(it.getObjectAt(0).toString()),
                (it.getObjectAt(2) as DEROctetString).octets ?: ByteArray(0)
            )
        }

        val objAt: (Int) -> ByteArray = { objs[it] ?: ByteArray(0) }
        val stringAt: (Int) -> String = { String(objAt(it)) }
        val instantAt: (Int) -> Instant = {
            stringAt(it).takeIf { it.isNotBlank() }?.let { Instant.parse(it) } ?: Instant.MIN
        }

        @Suppress("MagicNumber")
        return ReceiptPayload(
            appId = stringAt(2),
            attestationCertificate = readDerX509Certificate(objAt(3)),
            clientHash = objAt(4),
            token = stringAt(5),
            receiptType = ReceiptType.valueOf(stringAt(6)),
            environment = stringAt(7),
            creationTime = instantAt(12),
            riskMetric = stringAt(17).takeIf { it.isNotBlank() }?.let { Integer.parseInt(it) },
            notBefore = instantAt(19),
            expirationTime = instantAt(21),
        )
    }

    @Suppress("ThrowsCount")
    private fun verifyPayload(signedData: CMSSignedData, publicKey: PublicKey): ReceiptPayload {
        // 3. Parse the ASN.1 structure that makes up the payload.
        val receiptPayload = parseProperties(signedData)

        // 4. Verify that the receipt contains the App ID of your app in field 2.
        //    Your app’s App ID is the concatenation of your 10-digit Team ID, a period, and the app’s bundle ID.
        if (receiptPayload.appId != appId) {
            throw ReceiptException.InvalidPayload("Unexpected App ID: ${receiptPayload.appId}")
        }

        // 5. Verify that the receipt’s creation time, given in field 12, is no more than five minutes old.
        //    This helps to thwart replay attacks.
        if (receiptPayload.creationTime.isBefore(clock.instant().minus(maxAge))) {
            throw ReceiptException.InvalidPayload("Receipt's creation time is more than five minutes old")
        }

        // 6. Verify that the attested public key in field 3, encoded as a DER ASN.1 object,
        //    matches the one you stored after initial attestation.
        if (receiptPayload.attestationCertificate.publicKey != publicKey) {
            throw ReceiptException.InvalidPayload("Public key from receipt and attestation statement do not match")
        }

        return receiptPayload
    }

    enum class ReceiptType {
        ATTEST, RECEIPT
    }

    data class ReceiptPayload(
        val appId: String,
        // Apple: "attestedPublicKey"
        val attestationCertificate: X509Certificate,
        val clientHash: ByteArray,
        val token: String,
        val receiptType: ReceiptType,
        // Not mentioned in Apple's docs
        val environment: String,
        val creationTime: Instant,
        val riskMetric: Int?,
        val notBefore: Instant,
        val expirationTime: Instant,
    ) {
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
            result = 31 * result + environment.hashCode()
            result = 31 * result + creationTime.hashCode()
            result = 31 * result + (riskMetric ?: 0)
            result = 31 * result + notBefore.hashCode()
            result = 31 * result + expirationTime.hashCode()
            return result
        }
    }

    sealed class ReceiptException(message: String, cause: Throwable? = null) : RuntimeException(message, cause) {
        class InvalidCertificateChain(msg: String, cause: Throwable? = null) : ReceiptException(msg, cause)
        class InvalidSignature(msg: String) : ReceiptException(msg)
        class InvalidPayload(msg: String) : ReceiptException(msg)
    }
}
