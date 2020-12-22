package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.receipt.ReceiptValidator.Companion.APPLE_RECOMMENDED_MAX_AGE
import ch.veehait.devicecheck.appattest.util.Extensions.Pkcs7.readAsSignedData
import ch.veehait.devicecheck.appattest.util.Extensions.Pkcs7.readCertificateChain
import ch.veehait.devicecheck.appattest.util.Extensions.verifyChain
import ch.veehait.devicecheck.appattest.util.Utils
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.GeneralSecurityException
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Date

/**
 * Interface to validate the authenticity of an Apple App Attest receipt.
 *
 * @property app The connecting app.
 * @property trustAnchor The root of the receipt certificate chain.
 * @property maxAge The maximum validity period of a receipt. Defaults to [APPLE_RECOMMENDED_MAX_AGE] which reflects
 *   the value Apple recommends.
 * @property clock A clock instance. Defaults to the system clock. Should be only relevant for testing.
 */
interface ReceiptValidator {
    companion object {
        /** The maximum validity period of a receipt after issuing */
        @JvmField
        val APPLE_RECOMMENDED_MAX_AGE: Duration = Duration.ofMinutes(5)

        /** The root certificate authority of the signer of the receipt */
        @JvmField
        val APPLE_PUBLIC_ROOT_CA_G3_BUILTIN_TRUST_ANCHOR = TrustAnchor(
            Utils.readPemX509Certificate(
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

    val app: App
    val trustAnchor: TrustAnchor
    val maxAge: Duration
    val clock: Clock

    /**
     * Validate an Apple App Attest receipt. Suspending version of [validateReceipt].
     *
     * @see validateReceipt
     */
    suspend fun validateReceiptAsync(
        receiptP7: ByteArray,
        publicKey: ECPublicKey,
        notAfter: Instant = clock.instant().minus(maxAge),
    ): Receipt

    /**
     * Validate an Apple App Attest receipt.
     *
     * @param receiptP7 A DER-encoded PKCS #7 object received as part of an attestation statement or in response to
     *   a remote call to Apple's servers which exchanges an existing receipt for a new receipt.
     * @param publicKey The P-256 public key of the attestation object which is used to validate the [receiptP7].
     * @param notAfter An instant of time which marks the latest creation time for the passed [receiptP7] to be
     *   considered valid.
     * @return A validated [Receipt] which can be trusted.
     */
    fun validateReceipt(
        receiptP7: ByteArray,
        publicKey: ECPublicKey,
        notAfter: Instant = clock.instant().minus(maxAge),
    ): Receipt = runBlocking {
        validateReceiptAsync(receiptP7, publicKey, notAfter)
    }
}

/**
 * Implementation of [ReceiptValidator].
 *
 * Please note that this implementation only validates the receipt to the extent Apple describes. That means, the
 * validation procedure does not reject receipts which are not valid yet, i.e., have a [Receipt.Payload.notBefore] date
 * in the future (relative to [clock]), or have expired, i.e., have a [Receipt.Payload.expirationTime] which dates back
 * (again, relative to [clock]). This behavior is acceptable as both properties rather control the processing on Apple's
 * servers.
 *
 * @throws ReceiptException
 */
internal class ReceiptValidatorImpl(
    override val app: App,
    override val trustAnchor: TrustAnchor,
    override val maxAge: Duration,
    override val clock: Clock,
) : ReceiptValidator {

    override suspend fun validateReceiptAsync(
        receiptP7: ByteArray,
        publicKey: ECPublicKey,
        notAfter: Instant,
    ): Receipt = coroutineScope {
        val signedData = receiptP7.readAsSignedData()
        val certs = signedData.readCertificateChain()

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

    private fun verifyCertificateChain(certs: List<X509Certificate>) {
        try {
            certs.verifyChain(trustAnchor, date = Date.from(clock.instant()))
        } catch (ex: GeneralSecurityException) {
            throw ReceiptException.InvalidCertificateChain(
                "The receipt object does not contain a valid certificate chain",
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
    private fun verifyPayload(signedData: CMSSignedData, publicKey: ECPublicKey, notAfter: Instant): Receipt.Payload {
        // 3. Parse the ASN.1 structure that makes up the payload.
        val receiptPayload = Receipt.Payload.parse(signedData)

        // 4. Verify that the receipt contains the App ID of your app in field 2.
        //    Your app’s App ID is the concatenation of your 10-digit Team ID, a period, and the app’s bundle ID.
        if (receiptPayload.appId.value != app.appIdentifier) {
            throw ReceiptException.InvalidPayload("Unexpected App ID: ${receiptPayload.appId}")
        }

        // 5. Verify that the receipt’s creation time, given in field 12, is no more than five minutes old.
        //    This helps to thwart replay attacks.
        if (notAfter.isAfter(receiptPayload.creationTime.value)) {
            throw ReceiptException.InvalidPayload("Receipt's creation time is after $notAfter")
        }

        // 6. Verify that the attested public key in field 3, encoded as a DER ASN.1 object,
        //    matches the one you stored after initial attestation.
        if (receiptPayload.attestationCertificate.value.publicKey != publicKey) {
            throw ReceiptException.InvalidPayload("Public key from receipt and attestation statement do not match")
        }

        return receiptPayload
    }
}
