package ch.veehait.devicecheck.appattest.attestation

import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.common.AuthenticatorData
import ch.veehait.devicecheck.appattest.receipt.Receipt
import ch.veehait.devicecheck.appattest.receipt.ReceiptException
import ch.veehait.devicecheck.appattest.receipt.ReceiptValidator
import ch.veehait.devicecheck.appattest.util.Extensions.createAppleKeyId
import ch.veehait.devicecheck.appattest.util.Extensions.fromBase64
import ch.veehait.devicecheck.appattest.util.Extensions.get
import ch.veehait.devicecheck.appattest.util.Extensions.readObjectAs
import ch.veehait.devicecheck.appattest.util.Extensions.sha256
import ch.veehait.devicecheck.appattest.util.Extensions.verifyChain
import ch.veehait.devicecheck.appattest.util.Utils
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.util.Arrays.constantTimeAreEqual
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.cert.TrustAnchor
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.Clock
import java.util.Date

/**
 * Interface to validate the authenticity of an Apple App Attest attestation.
 *
 * @property app The connecting app.
 * @property appleAppAttestEnvironment The Apple App Attest environment; either "appattestdevelop" or "appattest".
 * @property trustAnchor The root of the App Attest certificate chain.
 * @property receiptValidator A [ReceiptValidator] to validate the receipt contained in the attestation statement.
 * @property clock A clock instance. Defaults to the system clock. Should be only relevant for testing.
 */
interface AttestationValidator {
    val app: App
    val appleAppAttestEnvironment: AppleAppAttestEnvironment
    val trustAnchor: TrustAnchor
    val receiptValidator: ReceiptValidator
    val clock: Clock

    companion object {
        /** X.509 extension object identifier which contains the nonce the app includes in the attestation call */
        const val APPLE_CRED_CERT_EXTENSION_OID = "1.2.840.113635.100.8.2"

        /** The root certificate authority of the attestation certificate */
        val APPLE_APP_ATTEST_ROOT_CA_BUILTIN_TRUST_ANCHOR = TrustAnchor(
            Utils.readPemX509Certificate(
                """
                -----BEGIN CERTIFICATE-----
                MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
                JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
                QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
                Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
                biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
                bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
                NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
                Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
                MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
                CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
                53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
                oyFraWVIyd/dganmrduC1bmTBGwD
                -----END CERTIFICATE-----
                """.trimIndent()
            ),
            null
        )
    }

    /**
     * Validate an attestation object.
     *
     * @param attestationObject attestation object created by calling
     *   `DCAppAttestService.attestKey(_:clientDataHash:completionHandler:)`
     * @param keyIdBase64 Base64-encoded key identifier which was created when calling
     *   `DCAppAttestService.generateKey(completionHandler:)`
     * @param serverChallenge The one-time challenge the server created. The iOS app incorporates a hash of this
     *   challenge in the call to `DCAppAttestService.attestKey(_:clientDataHash:completionHandler:)`
     *
     * @throws AttestationException If any attestation validation error occurs, an [AttestationException] is thrown.
     *
     * @return An [AppleAppAttestValidationResponse] object for the given [attestationObject].
     */
    fun validate(
        attestationObject: ByteArray,
        keyIdBase64: String,
        serverChallenge: ByteArray,
    ): AppleAppAttestValidationResponse

    /**
     * Validate an attestation object. Suspending version of [validate].
     *
     * @see validate
     */
    suspend fun validateAsync(
        attestationObject: ByteArray,
        keyIdBase64: String,
        serverChallenge: ByteArray,
    ): AppleAppAttestValidationResponse
}

@Suppress("TooManyFunctions")
internal class AttestationValidatorImpl(
    override val app: App,
    override val appleAppAttestEnvironment: AppleAppAttestEnvironment,
    override val clock: Clock,
    override val receiptValidator: ReceiptValidator,
    override val trustAnchor: TrustAnchor,
) : AttestationValidator {
    private val cborObjectReader = ObjectMapper(CBORFactory())
        .registerKotlinModule()
        .readerFor(AttestationObject::class.java)

    override suspend fun validateAsync(
        attestationObject: ByteArray,
        keyIdBase64: String,
        serverChallenge: ByteArray,
    ): AppleAppAttestValidationResponse = coroutineScope {
        val attestation = parseAttestationObject(attestationObject)
        val keyId = keyIdBase64.fromBase64()

        launch { verifyAttestationFormat(attestation) }
        launch { verifyCertificateChain(attestation) }
        launch { verifyNonce(attestation, serverChallenge) }
        val publicKey = async { verifyPublicKey(attestation, keyId) }
        launch { verifyAuthenticatorData(attestation, keyId) }
        val receipt = async {
            runCatching { validateAttestationReceiptAsync(attestation) }
                .getOrElse { throw AttestationException.InvalidReceipt(it) }
        }

        AppleAppAttestValidationResponse(publicKey.await(), receipt.await())
    }

    override fun validate(
        attestationObject: ByteArray,
        keyIdBase64: String,
        serverChallenge: ByteArray,
    ): AppleAppAttestValidationResponse = runBlocking {
        validateAsync(attestationObject, keyIdBase64, serverChallenge)
    }

    private fun parseAttestationObject(attestationObject: ByteArray): AttestationObject {
        return cborObjectReader.readValue(attestationObject)
    }

    private fun verifyAttestationFormat(attestationObject: AttestationObject) {
        if (attestationObject.fmt != AttestationObject.APPLE_APP_ATTEST_ATTESTATION_STATEMENT_FORMAT_IDENTIFIER) {
            throw AttestationException.InvalidFormatException(
                "Expected `${AttestationObject.APPLE_APP_ATTEST_ATTESTATION_STATEMENT_FORMAT_IDENTIFIER}` " +
                    "but was ${attestationObject.fmt}"
            )
        }
    }

    private fun verifyCertificateChain(attestationObject: AttestationObject) {
        // 1. Verify that the x5c array contains the intermediate and leaf certificates for App Attest,
        //    starting from the credential certificate stored in the first data buffer in the array (credcert).
        //    Verify the validity of the certificates using Apple’s App Attest root certificate.
        val certs = attestationObject.attStmt.x5c.map { Utils.readDerX509Certificate(it) }
        try {
            certs.verifyChain(trustAnchor, date = Date.from(clock.instant()))
        } catch (ex: GeneralSecurityException) {
            throw AttestationException.InvalidCertificateChain(
                "The attestation object does not contain a valid certificate chain",
                ex
            )
        }
    }

    /**
     * Extracts the nonce from the given [credCertDer] by reading Apple's extension value.
     *
     * The extension value is ASN.1 encoded and follows the following format:
     *
     *      OCTET STRING (38 byte)
     *          SEQUENCE (1 elem)
     *              [1] (1 elem)
     *                  OCTET STRING (32 byte)
     */
    private fun extractNonce(credCertDer: ByteArray): ByteArray {
        val credCert = Utils.readDerX509Certificate(credCertDer)
        val value = credCert.getExtensionValue(AttestationValidator.APPLE_CRED_CERT_EXTENSION_OID)
        val envelope = ASN1InputStream(value).readObjectAs<DEROctetString>()
        val sequence = ASN1InputStream(envelope.octetStream).readObjectAs<DLSequence>()
        val sequenceFirstObject = sequence.get<DLTaggedObject>(0)
        val leafOctetString = sequenceFirstObject.`object` as DEROctetString
        return leafOctetString.octets
    }

    private fun verifyNonce(attestationObject: AttestationObject, serverChallenge: ByteArray) {
        // 2. Create clientDataHash as the SHA256 hash of the one-time challenge sent to your app before performing
        //    the attestation, ...
        val clientDataHash = serverChallenge.sha256()

        //    ... and append that hash to the end of the authenticator data (authData from the decoded object).
        // 3. Generate a new SHA256 hash of the composite item to create nonce.
        val expectedNonce = attestationObject.authData.plus(clientDataHash).sha256()

        // 4. Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2, which is a DER-encoded
        //    ASN.1 sequence. Decode the sequence and extract the single octet string that it contains ...
        val actualNonce = kotlin.runCatching {
            extractNonce(attestationObject.attStmt.x5c.first())
        }.getOrElse {
            throw AttestationException.InvalidNonce(it)
        }

        //   ... Verify that the string equals nonce.
        if (!constantTimeAreEqual(expectedNonce, actualNonce)) {
            throw AttestationException.InvalidNonce()
        }
    }

    private fun verifyPublicKey(attestationObject: AttestationObject, keyId: ByteArray): ECPublicKey {
        // 5. Create the SHA256 hash of the public key in credCert, ...
        val credCert = X509CertificateHolder(attestationObject.attStmt.x5c.first())
        val actualKeyId = credCert.createAppleKeyId()

        //    ... and verify that it matches the key identifier from your app.
        if (!actualKeyId.contentEquals(keyId)) {
            throw AttestationException.InvalidPublicKey(keyId)
        }

        return KeyFactory
            .getInstance("EC")
            .generatePublic(X509EncodedKeySpec(credCert.subjectPublicKeyInfo.encoded)) as ECPublicKey
    }

    @Suppress("ThrowsCount")
    private fun verifyAuthenticatorData(attestationObject: AttestationObject, keyId: ByteArray) {
        val authenticatorData = AuthenticatorData.parse(attestationObject.authData)

        if (authenticatorData.attestedCredentialData == null) {
            throw AttestationException.InvalidAuthenticatorData("Does not contain attested credentials")
        }

        // 6. Compute the SHA256 hash of your app’s App ID, and verify that this is the same as the authenticator
        //    data’s RP ID hash.
        if (!authenticatorData.rpIdHash.contentEquals(app.appIdentifier.toByteArray().sha256())) {
            throw AttestationException.InvalidAuthenticatorData("App ID does not match RP ID hash")
        }

        // 7. Verify that the authenticator data’s counter field equals 0.
        if (authenticatorData.signCount != 0L) {
            throw AttestationException.InvalidAuthenticatorData("Counter is not zero")
        }

        // 8. Verify that the authenticator data’s aaguid field is either appattestdevelop if operating in the
        //    development environment, or appattest followed by seven 0x00 bytes if operating in the production
        //    environment.
        if (authenticatorData.attestedCredentialData.aaguid != appleAppAttestEnvironment.aaguid) {
            throw AttestationException.InvalidAuthenticatorData(
                "AAGUID does match neither ${AppleAppAttestEnvironment.DEVELOPMENT} " +
                    "nor ${AppleAppAttestEnvironment.PRODUCTION}"
            )
        }

        // 9. Verify that the authenticator data’s credentialId field is the same as the key identifier.
        if (!authenticatorData.attestedCredentialData.credentialId.contentEquals(keyId)) {
            throw AttestationException.InvalidAuthenticatorData("Credentials ID is not equal to Key ID")
        }
    }

    private suspend fun validateAttestationReceiptAsync(attestStatement: AttestationObject): Receipt {
        val receiptP7 = attestStatement.attStmt.receipt
        val attestationCertificate = attestStatement.attStmt.x5c.first().let(Utils::readDerX509Certificate)
        val publicKey = attestationCertificate.publicKey as ECPublicKey

        return try {
            receiptValidator.validateReceiptAsync(receiptP7, publicKey)
        } catch (ex: ReceiptException) {
            throw AttestationException.InvalidReceipt(ex)
        }
    }
}
