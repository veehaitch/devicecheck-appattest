package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.App
import ch.veehait.devicecheck.appattest.Extensions.verifyChain
import ch.veehait.devicecheck.appattest.Utils
import ch.veehait.devicecheck.appattest.attestation.AppleAppAttestStatement
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.GeneralSecurityException
import java.security.Security
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Date
import java.util.logging.Logger

interface ReceiptValidator {
    companion object {
        val APPLE_ATTESTATION_NOT_BEFORE_DILATION: Duration = Duration.ofDays(1)
        val APPLE_RECOMMENDED_MAX_AGE: Duration = Duration.ofMinutes(5)
    }

    val appId: String
    val trustAnchor: TrustAnchor
    val clock: Clock

    suspend fun validateAttestationReceiptAsync(
        attestStatement: AppleAppAttestStatement,
        notBeforeDilation: Duration = APPLE_ATTESTATION_NOT_BEFORE_DILATION,
        maxAge: Duration = APPLE_RECOMMENDED_MAX_AGE,
    ): Receipt

    fun validateAttestationReceipt(
        attestStatement: AppleAppAttestStatement,
        maxAge: Duration = APPLE_RECOMMENDED_MAX_AGE,
    ): Receipt

    suspend fun validateReceiptAsync(
        receiptP7: ByteArray,
        publicKey: ECPublicKey,
        notAfter: Instant = clock.instant().plus(APPLE_RECOMMENDED_MAX_AGE),
    ): Receipt

    fun validateReceipt(
        receiptP7: ByteArray,
        publicKey: ECPublicKey,
        notAfter: Instant = clock.instant().plus(APPLE_RECOMMENDED_MAX_AGE),
    ): Receipt
}

class ReceiptValidatorImpl(
    app: App,
    override val trustAnchor: TrustAnchor = APPLE_PUBLIC_ROOT_CA_G3_BUILTIN_TRUST_ANCHOR,
    override val clock: Clock = Clock.systemUTC(),
) : ReceiptValidator {
    companion object {
        private val logger = Logger.getLogger(this::class.java.simpleName)

        val APPLE_PUBLIC_ROOT_CA_G3_BUILTIN_TRUST_ANCHOR = TrustAnchor(
            Utils.readPemX590Certificate(
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
                """.trimIndent(),
            ),
            null
        )
    }

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    override val appId = app.appIdentifier

    override suspend fun validateAttestationReceiptAsync(
        attestStatement: AppleAppAttestStatement,
        notBeforeDilation: Duration,
        maxAge: Duration,
    ): Receipt = coroutineScope {
        val receiptP7 = attestStatement.attStmt.receipt
        val attestationCertificate = attestStatement.attStmt.x5c.first().let(Utils::readDerX509Certificate)
        val publicKey = attestationCertificate.publicKey as ECPublicKey
        val notAfter = attestationCertificate.notBefore.toInstant()
            .plus(notBeforeDilation)
            .plus(maxAge)

        validateReceiptAsync(receiptP7, publicKey, notAfter)
    }

    override fun validateAttestationReceipt(
        attestStatement: AppleAppAttestStatement,
        maxAge: Duration,
    ): Receipt = runBlocking {
        validateAttestationReceiptAsync(attestStatement, maxAge = maxAge)
    }

    override fun validateReceipt(
        receiptP7: ByteArray,
        publicKey: ECPublicKey,
        notAfter: Instant,
    ): Receipt = runBlocking {
        validateReceiptAsync(receiptP7, publicKey, notAfter)
    }

    override suspend fun validateReceiptAsync(
        receiptP7: ByteArray,
        publicKey: ECPublicKey,
        notAfter: Instant,
    ): Receipt = coroutineScope {
        val signedData = readSignedData(receiptP7)
        val certs = readCertificateChain(signedData)

        // 1. Verify the signature.
        launch { verifySignature(signedData, certs.first()) }

        // 2. Evaluate the trustworthiness of the signing certificate up to the
        //    Apple public root certificate for App Attest.
        launch { verifyCertificateChain(certs) }

        Receipt(
            payload = verifyPayload(signedData, publicKey, notAfter),
            p7 = receiptP7,
        )
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
            certs.verifyChain(trustAnchor, date = Date.from(clock.instant()))
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

    @Suppress("ThrowsCount")
    private fun verifyPayload(signedData: CMSSignedData, publicKey: ECPublicKey, notAfter: Instant): ReceiptPayload {
        // 3. Parse the ASN.1 structure that makes up the payload.
        val receiptPayload = ReceiptPayload.parse(signedData)

        // 4. Verify that the receipt contains the App ID of your app in field 2.
        //    Your app’s App ID is the concatenation of your 10-digit Team ID, a period, and the app’s bundle ID.
        if (receiptPayload.appId != appId) {
            throw ReceiptException.InvalidPayload("Unexpected App ID: ${receiptPayload.appId}")
        }

        // 5. Verify that the receipt’s creation time, given in field 12, is no more than five minutes old.
        //    This helps to thwart replay attacks.
        if (receiptPayload.creationTime.isAfter(notAfter)) {
            throw ReceiptException.InvalidPayload("Receipt's creation time is after $notAfter")
        }

        // 6. Verify that the attested public key in field 3, encoded as a DER ASN.1 object,
        //    matches the one you stored after initial attestation.
        if (receiptPayload.attestationCertificate.publicKey != publicKey) {
            throw ReceiptException.InvalidPayload("Public key from receipt and attestation statement do not match")
        }

        return receiptPayload
    }
}
