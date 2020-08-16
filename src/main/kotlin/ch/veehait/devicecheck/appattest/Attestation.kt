package ch.veehait.devicecheck.appattest

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput
import com.webauthn4j.util.ECUtil
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject
import org.bouncycastle.util.Arrays.constantTimeAreEqual
import java.security.SignatureException
import java.security.interfaces.ECPublicKey

/**
 * Class to validate the authenticity of an Apple App Attest attestation.
 *
 * The implementation closely follows the official article from Apple which outlines the necessary steps to validate
 * an attestation: https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
 *
 * @param appleTeamIdentifier Your 10-digit team identifier, as denoted on https://developer.apple.com/account.
 * @param appCfBundleIdentifier Your app’s CFBundleIdentifier value.
 * @param appleAppAttestRootCaPem Apple’s App Attest root certificate: https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem.
 * @param appleAppAttestEnvironment The Apple App Attest environment; either "appattestdevelop" or "appattest".
 */
class Attestation(
    appleTeamIdentifier: String,
    appCfBundleIdentifier: String,
    appleAppAttestRootCaPem: String,
    private val appleAppAttestEnvironment: AppleAppAttestEnvironment
) {
    companion object {
        const val APPLE_TEAM_IDENTIFIER_LENGTH = 10
        const val APPLE_CRED_CERT_EXTENSION_OID = "1.2.840.113635.100.8.2"
    }

    init {
        if (appleTeamIdentifier.length != APPLE_TEAM_IDENTIFIER_LENGTH) {
            throw IllegalArgumentException("The Apple team identifier must consist of exactly 10 digits")
        }
    }

    private val appId = "$appleTeamIdentifier.$appCfBundleIdentifier"
    private val appleAppAttestRootCa = readPemX590Certificate(appleAppAttestRootCaPem)
    private val cborObjectMapper = ObjectMapper(CBORFactory()).registerKotlinModule()

    /**
     * Validate an attestation object. Suspending version of [validate].
     *
     * @see validate
     */
    suspend fun validateAsync(
        attestationObjectBase64: String,
        keyIdBase64: String,
        serverChallenge: ByteArray
    ): AppleAppAttestValidationResponse = coroutineScope {
        val attestationStatement = parseAttestationObject(attestationObjectBase64)
        val keyId = keyIdBase64.fromBase64()

        launch { verifyAttestationFormat(attestationStatement) }
        launch { verifyCertificateChain(attestationStatement) }
        launch { verifyNonce(attestationStatement, serverChallenge) }
        val publicKey = async { verifyPublicKey(attestationStatement, keyId) }
        launch { verifyAuthenticatorData(attestationStatement, keyId) }

        AppleAppAttestValidationResponse(publicKey.await(), attestationStatement.attStmt.receipt)
    }

    /**
     * Validate an attestation object.
     *
     * @param attestationObjectBase64 Base64-encoded attestation object created by calling
     *  `DCAppAttestService#attestKey(_:clientDataHash:completionHandler:)`
     * @param keyIdBase64 Base64-encoded key identifier which was created when calling
     *  `DCAppAttestService#generateKey(completionHandler:)`
     * @param serverChallenge The one-time challenge the server created. The iOS app incorporates a hash of this
     *  challenge in the call to `DCAppAttestService#attestKey(_:clientDataHash:completionHandler:)`
     *
     * @throws AttestationException If any attestation validation error occurs, an [AttestationException] is thrown.
     *
     * @return An [AppleAppAttestStatement] object for the given [attestationObjectBase64].
     */
    fun validate(
        attestationObjectBase64: String,
        keyIdBase64: String,
        serverChallenge: ByteArray
    ): AppleAppAttestValidationResponse = runBlocking {
        validateAsync(attestationObjectBase64, keyIdBase64, serverChallenge)
    }

    private fun parseAttestationObject(attestationObjectBase64: String): AppleAppAttestStatement {
        val attestationObjectCbor = attestationObjectBase64.fromBase64()
        return cborObjectMapper.readValue(attestationObjectCbor, AppleAppAttestStatement::class.java)
    }

    private fun parseAuthenticatorData(appleAppAttestStatement: AppleAppAttestStatement): AuthenticatorData<*> {
        val converter = AuthenticatorDataConverter(
            ObjectConverter(ObjectMapper().registerKotlinModule(), cborObjectMapper)
        )
        return converter.convert<AuthenticationExtensionAuthenticatorOutput<*>>(appleAppAttestStatement.authData)
    }

    private fun verifyAttestationFormat(appleAppAttestStatement: AppleAppAttestStatement) {
        if (appleAppAttestStatement.fmt != AppleAppAttestStatement.APPLE_ATTESTATION_FORMAT_NAME) {
            throw AttestationException.InvalidFormatException(
                "Expected `${AppleAppAttestStatement.APPLE_ATTESTATION_FORMAT_NAME}` " +
                    "but was ${appleAppAttestStatement.fmt}"
            )
        }
    }

    private fun verifyCertificateChain(appleAppAttestStatement: AppleAppAttestStatement) {
        // 1. Verify that the x5c array contains the intermediate and leaf certificates for App Attest,
        //    starting from the credential certificate stored in the first data buffer in the array (credcert).
        //    Verify the validity of the certificates using Apple’s App Attest root certificate.
        try {
            val certs = appleAppAttestStatement.attStmt.x5c.map {
                readDerX509Certificate(it)
            } + listOf(appleAppAttestRootCa)

            (certs + certs.last()).windowed(2, 1).forEach { (child, parent) ->
                child.verify(parent.publicKey)
            }
        } catch (ex: SignatureException) {
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
        val credCert = readDerX509Certificate(credCertDer)
        val value = credCert.getExtensionValue(APPLE_CRED_CERT_EXTENSION_OID)
        val envelope = ASN1InputStream(value).readObject() as DEROctetString
        val sequence = ASN1InputStream(envelope.octetStream).readObject() as DLSequence
        val sequenceFirstObject = sequence.objects.toList().first() as DLTaggedObject
        val leafOctetString = sequenceFirstObject.`object` as DEROctetString
        return leafOctetString.octets
    }

    private fun verifyNonce(appleAppAttestStatement: AppleAppAttestStatement, serverChallenge: ByteArray) {
        // 2. Create clientDataHash as the SHA256 hash of the one-time challenge sent to your app before performing
        //    the attestation, ...
        val clientDataHash = serverChallenge.sha256()

        //    ... and append that hash to the end of the authenticator data (authData from the decoded object).
        // 3. Generate a new SHA256 hash of the composite item to create nonce.
        val expectedNonce = (appleAppAttestStatement.authData + clientDataHash).sha256()

        // 4. Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2, which is a DER-encoded
        //    ASN.1 sequence. Decode the sequence and extract the single octet string that it contains ...
        val actualNonce = kotlin.runCatching {
            extractNonce(appleAppAttestStatement.attStmt.x5c.first())
        }.getOrElse {
            throw AttestationException.InvalidNonce(it)
        }

        //   ... Verify that the string equals nonce.
        if (!constantTimeAreEqual(expectedNonce, actualNonce)) {
            throw AttestationException.InvalidNonce()
        }
    }

    private fun verifyPublicKey(appleAppAttestStatement: AppleAppAttestStatement, keyId: ByteArray): ECPublicKey {
        // 5. Create the SHA256 hash of the public key in credCert, ...
        val credCert = readDerX509Certificate(appleAppAttestStatement.attStmt.x5c.first())
        val publicKey = credCert.publicKey as ECPublicKey
        val uncompressedPublicKey = ECUtil.createUncompressedPublicKey(publicKey)
        val actualKeyId = uncompressedPublicKey.sha256()

        //    ... and verify that it matches the key identifier from your app.
        if (!actualKeyId.contentEquals(keyId)) {
            throw AttestationException.InvalidPublicKey(keyId)
        }

        return publicKey
    }

    @Suppress("ThrowsCount")
    private fun verifyAuthenticatorData(appleAppAttestStatement: AppleAppAttestStatement, keyId: ByteArray) {
        val authenticatorData = parseAuthenticatorData(appleAppAttestStatement)

        // 6. Compute the SHA256 hash of your app’s App ID, and verify that this is the same as the authenticator
        //    data’s RP ID hash.
        if (!authenticatorData.rpIdHash!!.contentEquals(appId.toByteArray().sha256())) {
            throw AttestationException.InvalidAuthenticatorData("App ID does not match RP ID hash")
        }

        // 7. Verify that the authenticator data’s counter field equals 0.
        if (authenticatorData.signCount != 0L) {
            throw AttestationException.InvalidAuthenticatorData("Counter is not zero")
        }

        // 8. Verify that the authenticator data’s aaguid field is either appattestdevelop if operating in the
        //    development environment, or appattest followed by seven 0x00 bytes if operating in the production
        //    environment.
        if (authenticatorData.attestedCredentialData.aaguid != appleAppAttestEnvironment.asAaguid()) {
            throw AttestationException.InvalidAuthenticatorData(
                "AAGUID does match neither ${AppleAppAttestEnvironment.DEVELOPMENT.identifier} " +
                    "nor ${AppleAppAttestEnvironment.PRODUCTION.identifier}"
            )
        }

        // 9. Verify that the authenticator data’s credentialId field is the same as the key identifier.
        if (!authenticatorData.attestedCredentialData.credentialId!!.contentEquals(keyId)) {
            throw AttestationException.InvalidAuthenticatorData("Credentials ID is not equal to Key ID")
        }
    }
}

sealed class AttestationException(message: String, cause: Throwable?) : RuntimeException(message, cause) {
    class InvalidFormatException(message: String, cause: Throwable? = null) : AttestationException(message, cause)
    class InvalidCertificateChain(message: String, cause: Throwable? = null) : AttestationException(message, cause)
    class InvalidNonce(cause: Throwable? = null) : AttestationException("The attestation's nonce is invalid", cause)
    class InvalidPublicKey(keyId: ByteArray)
        : AttestationException("Expected key identifier '${keyId.toBase64()}'", null)

    class InvalidAuthenticatorData(message: String) : AttestationException(message, null)
}
